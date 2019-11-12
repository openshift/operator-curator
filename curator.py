#!/usr/bin/env python3
"""
The app registry curator is a tool that scans Quay.io app registries in
order to vet operators for use with OSD v4.
"""

import argparse
import base64
import itertools
import json
import logging
from pathlib import Path
import shutil
import sys
import tarfile
import requests
import yaml


SOURCE_NAMESPACES = [
    "redhat-operators",
    "certified-operators",
    "community-operators"
]

ALLOWED_PACKAGES = [
    "redhat-operators/cluster-logging",
    "redhat-operators/elasticsearch-operator",
    "redhat-operators/codeready-workspaces"
]

DENIED_PACKAGES = [
    "certified-operators/mongodb-enterprise",
    "community-operators/etcd",
    "community-operators/federation",
    "community-operators/syndesis"
]


def _url(path):
    return "https://quay.io/cnr/api/v1/" + path


def _repo_url(path):
    return "https://quay.io/api/v1/" + path


def _quay_headers(authtoken):
    return {
        "Authorization" : authtoken,
        "Content-Type": "application/json"
    }


def _pkg_shortname(package):
    """
    Strips out the package's namespace and returns its shortname.
    """
    return package.split('/')[1]


def _pkg_namespace(package):
    """
    Strips out the package name and returns its namespace.
    """
    return package.split('/', 1)[0]


def _pkg_curated_namespace(package):
    """
    Strips out the package name and returns its curated namespace.
    """
    return f"curated-{package.split('/', 1)[0]}"


def list_operators(namespace):
    '''List the operators in the provided quay app registry namespace'''
    r = requests.get(_url(f"packages?namespace={namespace}"))
    if r.ok:
        l = [str(e['name']) for e in r.json()]
        return l

    return None


def get_release_data(operator):
    """
    Gets all the release versions for an operator package,
    eg: redhat-operators/codeready-workspaces, and returns a list of
    dictionaries with release version, package name, and its digests.
    """
    releases = []
    r = requests.get(_url(f"packages/{operator}"))
    if r.ok:
        for release in r.json():
            releases.append(
                {
                    "package": release['package'],
                    "digest": str(release['content']['digest']),
                    "version": release['release'],
                    "namespace": _pkg_namespace(release['package'])
                }
            )
    return releases


def curated(package, version):
    """
    Check for the package in the curated namespace, and return the result.
    """
    curated = [i for i in get_release_data(package) if version in i.values()]

    return curated


def set_repo_visibility(namespace, package_shortname, oauth_token, public=True,):
    '''Set the visibility of the specified app registry in Quay.'''
    # NEEDS TEST
    s = requests.sessions.Session()

    visibility = "public" if public else "private"

    logging.info(f"Setting visibility of {namespace}/{package_shortname} to {'public' if public else 'private'}")

    try:
        r = s.post(
            _repo_url(f"repository/{namespace}/{package_shortname}/changevisibility"),
            json={"visibility": visibility},
            headers=_quay_headers(f"Bearer {oauth_token}")
        )
        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        logging.error(f"Failed to set visibility of {namespace}/{package_shortname}. HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        logging.error(f"Failed to set visibility of {namespace}/{package_shortname}. Connection Error: {errc}")
    except requests.exceptions.Timeout as errt:
        logging.error(f"Failed to set visibility of {namespace}/{package_shortname}. Timeout Error: {errt}")


def get_package_release(release, use_cache):
    """
    Downloads the tarball package for the release.
    """
    # NEEDS TEST
    package = release['package']
    version = release['version']
    digest = release['digest']

    outfile = Path(f"{package}/{version}/{_pkg_shortname(package)}.tar.gz")

    if use_cache and Path.exists(outfile):
        return

    r = requests.get(
        _url(f"packages/{package}/blobs/sha256/{digest}"),
        stream=True
    )

    outfile.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(outfile, 'wb') as f:
            shutil.copyfileobj(r.raw, f)
    finally:
        del r


def check_package_in_allow_list(package):
    """
    Returns true if the packaged has been listed in the allow list,
    regardless of other heuristics.  Also returns the test name.
    """
    logging.debug("Checking if package is in the allow list")
    test_name = 'Package is in allowed list'
    if package in ALLOWED_PACKAGES:
        return test_name, True

    return test_name, False


def check_package_in_deny_list(package):
    """
    Returns true if the packaged has been listed in the denly list,
    regardless of other heuristics.  Also returns the test name.
    """
    logging.debug("Checking if package is in the deny list")
    test_name = 'Package is in denied list'
    if package in DENIED_PACKAGES:
        return test_name, True

    return test_name, False


def extract_bundle_from_tar_file(operator_tarfile):
    """
    Extracts the bundle.yaml file from the tar object provides.
    Returns the bundle.yaml object, test name, and result.
    """
    logging.debug("Extracting bundle.yaml from tarfile")

    test_name = 'bundle.yaml must be present'
    with tarfile.open(operator_tarfile) as t:
        try:
            bundle_file = t.extractfile(
                [i for i in t if Path(i.name).name == "bundle.yaml"][0]
            ).read()
            result = True
        except IndexError:
            bundle_file = None
            result = False
        except TypeError:
            bundle_file = None
            result = False

    return bundle_file, test_name, result


def load_yaml_from_bundle_object(bundle_yaml_obj):
    """
    Loads the yaml from the bundle object and returns a failure if
    it is unable to.  Also returns the test name and result.
    """
    logging.debug("Loading bundle.yaml data")

    test_name = 'bundle.yaml must be parsable'
    try:
        bundle_yaml = yaml.safe_load(bundle_yaml_obj)
    except yaml.YAMLError:
        bundle_yaml = None
        result = False
    else:
        result = True

    return bundle_yaml, test_name, result


def get_entry_from_bundle(bundle_yaml, entry):
    """
    Tests whether or not a particular entry is contained in the bundle.yaml,
    and returns it if so, and returns the test name and result.
    """
    logging.debug(f"Loading {entry} list from bundle")

    test_name = f"bundle must have a {entry} object"
    try:
        data = yaml.safe_load(bundle_yaml['data'][entry])
    except yaml.YAMLError:
        data = None
        result = False
    except TypeError:
        data = None
        result = False
    else:
        result = True

    return data, test_name, result


def validate_csv(package, version, csv):
    """
    Checks csv for prohibited clusterPermissions,
    multi-namespace install mode, and security context constraints.
    """

    # Aggregates CSV sub-tests, returns dict of results
    # test_name =
    # return [X], test_name, result

    #check_csv_for_clusterpermissions()
    #check_csv_for_securitycontextconstraints()
    #check_csv_for_multinamespace_installmode()

    tests = {}
    # Cluster Permissions aren't allowed
    cpKey = "CSV must not include clusterPermissions"
    tests[cpKey] = True
    if 'clusterPermissions' in csv['spec']['install']['spec']:
        logging.info(f"[FAIL] {package} version {version} requires clusterPermissions")
        tests[cpKey] = False
    # Using SCCs isn't allowed
    sccKey = "CSV must not grant SecurityContextConstraints permissions"
    tests[sccKey] = True
    if 'permissions' in csv['spec']['install']['spec']:
        for rules in csv['spec']['install']['spec']['permissions']:
            for i in rules['rules']:
                if ("security.openshift.io" in i['apiGroups'] and
                        "use" in i['verbs'] and
                        "securitycontextconstraints" in i['resources']):
                    logging.info(f"[FAIL] {package} version {version} requires security context constraints")
                    tests[sccKey] = False
    # installMode == MultiNamespace is not allowed
    multiNsKey = "CSV must not require MultiNamespace installMode"
    tests[multiNsKey] = True
    for im in csv['spec']['installModes']:
        if im['type'] == "MultiNamespace" and im['supported'] is True:
            logging.info(f"[FAIL] {package} version {version} supports multi-namespace install mode")
            tests[multiNsKey] = False

    result = bool(all(tests.values()))
    return result, tests


def regenerate_bundle_yaml(bundle_yaml, packages,
                           customResourceDefinitions, csvsByChannel):
    """
    Regenerates the bundle yaml with curated CSV data
    """
    csvs = []
    # For every channel, carry over the curated CSVs, and reset the 'replaces' field for the last one
    for channel in csvsByChannel:
        channelCSVs = csvsByChannel[channel]

        channelCSVs[-1]['spec'].pop('replaces', None)
        csvs += channelCSVs

    # Override CSVs in the original bundle, default to pipe delimited valus to support longer fields
    bundle_yaml['data']['clusterServiceVersions'] = yaml.dump(csvs, default_style='|')
    bundle_yaml['data']['customResourceDefinitions'] = yaml.dump(customResourceDefinitions, default_style='|')
    bundle_yaml['data']['packages'] = yaml.dump(packages, default_style='|')

    return bundle_yaml


def validate_bundle(release):
    """
    Review the bundle.yaml for a package to check that it is
    appropriate for use with OSD.
    """
    package = release['package']
    version = release['version']
    shortname = _pkg_shortname(package)

    tar_file = Path(f"{package}/{version}/{shortname}.tar.gz")
    bundle_filename = "bundle.yaml"
    bundle_file = Path(f"./{package}/{version}/{bundle_filename}")

    tests = {}
    csvsByChannel = {}
    truncatedBundle = False

    logging.info(f"Validating bundle for {package} version {version}")

    # Any package in our allow list is valid, regardless of other heuristics
    name, result = check_package_in_allow_list(package)

    if result:
        logging.info(f"[PASS] {package} (all versions) {name}")
        # ONLY return test result if it is in the list
        tests[name] = result
        return True, tests

    # Any package in our deny is invalid; skip further processing
    name, result = check_package_in_deny_list(package)

    if result:
        logging.info(f"[FAIL] {package} (all versions) {name}")
        # ONLY return test result if it is in the list
        # For this one test, a positive result means it *FAILS*
        # Send false to the summary, instead of the result
        tests[name] = False
        return False, tests

    # Extract the bundle.yaml file
    bundle_yaml_object, name, result = extract_bundle_from_tar_file(tar_file)

    tests[name] = result
    logging.info(f"{'[PASS]' if result else '[FAIL]'} {package} (all versions) {name}")

    # If extracting the bundle fails, no further processing is possible
    if not result:
        return False, tests

    # Load the yaml from the bundle object to a variable
    bundle_yaml, name, result = load_yaml_from_bundle_object(bundle_yaml_object)
    tests[name] = result
    logging.info(f"{'[PASS]' if result else '[FAIL]'} {package} (all versions) {name}")

    # If reading the yaml file fails, no further processing is possible
    if not result:
        return False, tests

    # Retrieve the package list from the bundle
    packages, name, result = get_entry_from_bundle(
        bundle_yaml, 'packages')
    tests[name] = result
    logging.info(f"{'[PASS]' if result else '[FAIL]'} {package} (all versions) {name}")

    # If packages didn't exist in the bundle file, no further processing is possible
    if not result:
        return False, tests

    # Retrieve the csv list from the bundle
    csvs, name, result = get_entry_from_bundle(
        bundle_yaml, 'clusterServiceVersions')
    tests[name] = result
    logging.info(f"{'[PASS]' if result else '[FAIL]'} {package} (all versions) {name}")

    # If csvs didn't exist in the bundle file, no further processing is possible
    if not result:
        return False, tests

    # Retrieve any CRDs from the bundle; not a test
    customResourceDefinitions, _, _ = get_entry_from_bundle(
        bundle_yaml,
        "customResourceDefinitions"
    )

    # The rest of this function needs to be refactord into
    # smaller, simpler functions, and have tests added

    # The package might have multiple channels, loop thru them
    logging.debug("Validating individual channels in package")
    for channel in packages[0]['channels']:
        logging.debug(f"Validating channel {channel['name']}")

        goodCSVs = []
        channelKey = f"Curated channel: {channel['name']}"
        tests[channelKey] = False
        latestCSVname = channel['currentCSV']
        latestCSV = get_csv_from_name(csvs, latestCSVname)
        valPass, latestCSVTests = validate_csv(package,
                                               version,
                                               latestCSV)
        latestCSVkey = "The most recent CSV must pass curation"
        latestCSVTests[latestCSVkey] = True

        # Latest CSV was rejected, we reject the entire bundle
        if not valPass:
            latestCSVTests[latestCSVkey] = False
            return valPass, latestCSVTests

        latestBundleKey = f"CSV {latestCSV['metadata']['name']} curated"
        tests[latestBundleKey] = True

        goodCSVs.append(latestCSV)

        replacesCSVName = latestCSV['spec'].get('replaces')
        while replacesCSVName:
            nextCSV = get_csv_from_name(csvs, replacesCSVName)
            nextCSVPass, _ = validate_csv(package, version, nextCSV)

            if nextCSVPass:
                goodCSVs.append(nextCSV)
                nextCSVPassKey = f"CSV {replacesCSVName} curated"
                tests[nextCSVPassKey] = True
                # Refresh the pointer to the 'replaces' tag
                replacesCSVName = nextCSV.get('replaces')
            else:
                # If this CSV does not pass curation, we truncate the bundle
                # But we do not reject the entire bundle
                nextCSVRejKey = f"CSV {replacesCSVName} rejected, truncating bundle here"
                tests[nextCSVRejKey] = True
                truncatedBundle = True
                break

        csvsByChannel[channel['name']] = goodCSVs
        tests[channelKey] = True

    # If the bundle was truncated we need to regen the bundle file and links
    if truncatedBundle:
        replacement_bundle_yaml = regenerate_bundle_yaml(
            bundle_yaml,
            packages,
            customResourceDefinitions,
            csvsByChannel)

        with open(bundle_file, 'w') as outfile:
            yaml.dump(replacement_bundle_yaml, outfile, default_style='|')

        # Create tar.gz file, forcing the bundle file to sit in the root of the tar vol
        with tarfile.open(tar_file, "w:gz") as tar_handle:
            tar_handle.add(bundle_file, arcname=bundle_filename)

    # If all of the values for dict "tests" are True, return True
    # otherwise return False (operator validation has failed!)
    result = bool(all(tests.values()))
    return result, tests


def get_csv_from_name(csvs, csvName):
    """
    Returns a cluster service version from the csv name
    """
    for csv in csvs:
        if csv['metadata']['name'] == csvName:
            return csv

    return None


def push_package(release, target_namespace, oauth_token, basic_token):
    '''
    Push package on disk into a target quay namespace.
    '''
    package = release['package']
    version = release['version']

    shortname = _pkg_shortname(package)

    with open(f"{package}/{version}/{shortname}.tar.gz", 'rb') as f:
        encoded_bundle = base64.b64encode(f.read())
        encoded_bundle_str = encoded_bundle.decode()

    payload = {
        "blob": encoded_bundle_str,
        "release": version,
        "media_type": "helm"
    }

    try:
        logging.info(f"Pushing {shortname} to the {target_namespace} namespace")
        r = requests.post(_url(f"packages/{target_namespace}/{shortname}"), data=json.dumps(payload), headers=_quay_headers(basic_token))
        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        if r.status_code == 409:
            logging.info(f"Version {version} of {shortname} is already present in {target_namespace} namespace. Skipping...")
        else:
            logging.error(f"Failed to upload {shortname} to {target_namespace} namespace. HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        logging.error(f"Failed to upload {shortname} to {target_namespace} namespace. Connection Error: {errc}")
    except requests.exceptions.Timeout as errt:
        logging.error(f"Failed to upload {shortname} to {target_namespace} namespace. Timeout Error: {errt}")

    # This is a new package namespace, make it publicly visible
    set_repo_visibility(target_namespace, shortname, oauth_token)


def summarize(summary, out=sys.stdout):
    """Summarize prints a summary of results for human readability."""

    if not isinstance(summary, list):
        raise TypeError()
    if not summary:
        raise IndexError()


    report = []

    passing_count = len([i for i in summary if {key:value for (key, value) in i.items() if value["pass"]}])
    skipped_count = len([i for i in summary if {key:value for (key, value) in i.items() if value["skipped"]}])
    for i in summary:
        for operator, info in i.items():
            operator_result = "[PASS]" if info["pass"] else "[FAIL]"
            report.append(f"\n{operator_result} {operator} version {info['version']}")
            for name, result in info["tests"].items():
                test_result = "[PASS]" if result else "[FAIL]"
                report.append(f"    {test_result} {name}")

    report_str = "\n".join(report)

    # Not as readable as printing, but prepping for unittesting
    out.write(
        f"\nValidation Summary\n"
        f"------------------\n"
        f"{report_str}\n"
        f"\n"
        f"Passed Curation: {passing_count - skipped_count}\n"
        f"Already Curated: {skipped_count}\n"
        f"Failed Curation: {len(summary) - passing_count}\n"
    )


if __name__ == "__main__":

    PARSER = argparse.ArgumentParser(
        description=("""A tool for curating application registry for
            use with OSDv4."""))
    PARSER.add_argument(
        '--app-token', action="store",
        dest="basic_token", type=str,
        help="Basic auth token for use with Quay's CNR API")
    PARSER.add_argument(
        '--oauth-token', action="store",
        dest="oauth_token", type=str,
        help="Oauth token for use with Quay's repository API")
    PARSER.add_argument(
        '--cache', action="store_true",
        default=False, dest="use_cache",
        help="Use local cache of operator packages")
    PARSER.add_argument(
        '--skip-push', action="store_true",
        default=False, dest="skip_push",
        help="Skip pushing validated packages to Quay.io")
    PARSER.add_argument(
        '--log-level', action="store",
        default='info', dest="log_level", type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Set verbosity of logs printed to STDOUT.")
    ARGS = PARSER.parse_args()

    LOGLEVEL = getattr(logging, ARGS.log_level.upper(), None)
    logging.basicConfig(level=LOGLEVEL)

    SUMMARY = []

    logging.info("Downloading operator data from source namespaces.")
    OPERATORS = [list_operators(ns) for ns in SOURCE_NAMESPACES]

    logging.info("Downloading release data for operators.")
    RELEASES = [
        get_release_data(o) for o in list(itertools.chain(*OPERATORS))
    ]

    logging.info("Beginning validation testing of release versions.")
    for release in list(itertools.chain(*RELEASES)):

        shortname = _pkg_shortname(release['package'])
        version = release['version']
        namespace = _pkg_namespace(release['package'])
        curated_namespace = _pkg_curated_namespace(release['package'])
        curated_package_name = f"{curated_namespace}/{shortname}"

        get_package_release(release, ARGS.use_cache)

        # Don't try to push if the specific package version is already
        # present in our target namespace
        if curated(curated_package_name, version):
            curated_message = (
                f"[SKIP] {curated_package_name} "
                f"version {version} already curated"
            )
            SUMMARY.append(
                {
                    release['package']: {
                        "version": version,
                        "pass": True,
                        "skipped": True,
                        "tests": {curated_message: True}
                    }
                }
            )
            logging.info(f"{curated_message}, skipping")
        else:
            passed, info = validate_bundle(release)
            SUMMARY.append(
                {release['package']: {
                    "version": release['version'],
                    "pass": passed,
                    "skipped": False,
                    "tests": info}
                }
            )
            logging.info(
                f"{release['package']}:{version} "
                f"{'PASSED' if passed else 'FAILED'} "
                f"validation for use with OSD"
            )

            if passed and not ARGS.skip_push:
                push_package(
                    release,
                    curated_namespace,
                    ARGS.oauth_token,
                    ARGS.basic_token,
                )

    summarize(SUMMARY)
