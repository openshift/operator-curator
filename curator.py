#!/usr/bin/env python3
"""
The app registry curator is a tool that scans Quay.io app registries in order to vet operators for use with OSD v4.
"""

import argparse
import base64
import json
import logging
from pathlib import Path
import tarfile
import shutil
import sys
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
    ''' Strips out the package's namespace and returns its shortname '''
    return package.split('/')[1]

def get_package_releases(package):
    '''Returns a dictionary with each version and digest available for a package'''
    releases = {}
    r = requests.get(_url(f"packages/{package}"))
    if r.ok:
        for release in r.json():
            releases[str(release['release'])] = str(release['content']['digest'])
    return releases

def list_operators(namespace):
    '''List the operators in the provided quay app registry namespace'''
    r = requests.get(_url(f"packages?namespace={namespace}"))
    l = [str(e['name']) for e in r.json()]
    return l

def set_repo_visibility(namespace, package_shortname, oauth_token, public=True,):
    '''Set the visibility of the specified app registry in Quay.'''
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

def retrieve_package(package, version, use_cache):
    '''Downloads an operator's package from quay'''
    if use_cache:
        logging.debug(f"Using local cache for package {package}  version {version}")
        return

    logging.info(f"Downloading package {package} version {version}")
    r = requests.get(_url(f"packages/{package}"))
    digest = [str(i['content']['digest']) for i in r.json() if i['release'] == version][0]
    r = requests.get(_url(f"packages/{package}/blobs/sha256/{digest}"), stream=True)
    outfile_path = Path(f"{package}/{version}/{_pkg_shortname(package)}.tar.gz")

    outfile_path.parent.mkdir(parents=True, exist_ok=True)

    with open(outfile_path, 'wb') as out_file:
        shutil.copyfileobj(r.raw, out_file)
    del r


def validate_bundle(package, version):
    '''
    Review the bundle.yaml for a package to check that it is appropriate for use with OSD.
    '''
    tests = {}
    csvsByChannel = {}
    truncatedBundle = False
    bundle_filename = "bundle.yaml"
    bundle_file = Path(f"./{package}/{version}/{bundle_filename}")

    logging.info(f"Validating bundle for {package} version {version}")

    shortname = _pkg_shortname(package)

    # Any package in our allow list is valid, regardless of other heuristics
    if package in ALLOWED_PACKAGES:
        logging.info(f"[PASS] {package} version {version} is in the allowed list.")
        tests["is in allowed list"] = True
        return True, tests

    # Any package in our blacklist is invalid; skip further processing
    if package in DENIED_PACKAGES:
        logging.info(f"[FAIL] {package} version {version} is in the deny list")
        tests["is in denied list"] = False
        return False, tests

    with tarfile.open(f"{package}/{version}/{shortname}.tar.gz") as t:
        try:
            bf = t.extractfile([i for i in t if Path(i.name).name == "bundle.yaml"][0])
            tests["bundle.yaml must be present"] = True
        except IndexError:
            # Cannot perform tests; skip further processing
            logging.warning(f"[FAIL] Cannot validate {package} version {version}: 'bundle.yaml' not present in package")
            tests["bundle.yaml must be present"] = False
            return False, tests
        except KeyError:
            # Cannot perform tests; skip further processing
            logging.warning(f"[FAIL] Cannot validate {package} version {version}: 'bundle.yaml' not present in package")
            tests["bundle.yaml must be present"] = False
            return False, tests
        by = yaml.safe_load(bf.read())

        # Load array of CSVs
        csvs = yaml.safe_load(by['data']['clusterServiceVersions'])
        # Lodd array of CRDs
        customResourceDefinitions = yaml.safe_load(by['data']['customResourceDefinitions'])

        # Check if the bundle has a package
        packKey = "Bundle must have a package object"
        tests[packKey] = True
        packages = yaml.safe_load(by['data']['packages'])
        if not packages:
            tests[packKey] = False
            return False, tests


        # The package might have multiple channels, loop thru them
        for channel in packages[0]['channels']:
            goodCSVs = []
            channelKey = f"Curated channel: {channel['name']}"
            tests[channelKey] = False
            latestCSVname = channel['currentCSV']
            latestCSV = get_csv_from_name(csvs, latestCSVname)
            valPass, latestCSVTests = validate_csv(package, version, latestCSV)
            latestCSVkey = "The CSV for the latest version must pass curation"
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

                if not nextCSVPass:
                    # If this CSV does not pass curation, we truncate the bundle
                    # But we do not reject the entire bundle
                    nextCSVRejKey = f"CSV {replacesCSVName} rejected, truncating bundle here"
                    tests[nextCSVRejKey] = True
                    truncatedBundle = True
                    break
                else:
                    goodCSVs.append(nextCSV)
                    nextCSVPassKey = f"CSV {replacesCSVName} curated"
                    tests[nextCSVPassKey] = True
                    # Refresh the pointer to the 'replaces' tag
                    replacesCSVName = nextCSV.get('replaces')

            csvsByChannel[channel['name']] = goodCSVs
            tests[channelKey] = True

        # If the bundle was truncated we need to regen the bundle file and links
        if truncatedBundle:
            logging.warning(f"{package} version {version} - writing truncated bundle to tarfile")
            by = regenerate_bundle_yaml(
                by,
                packages,
                customResourceDefinitions,
                csvsByChannel)

            with open(bundle_file, 'w') as outfile:
                yaml.dump(by, outfile, default_style='|')

        # Create tar.gz file, forcing the bundle file to sit in the root of the tar vol
        with tarfile.open(f"{package}/{version}/{shortname}.tar.gz", "w:gz") as tar_handle:
            tar_handle.add(bundle_file, arcname=bundle_filename)

    # If all of the values for dict "tests" are True, return True
    # otherwise return False (operator validation has failed!)
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


def validate_csv(package, version, csv):
    """
    Checks csv to make sure there are no clusterPermissions,
    it does not support multi-namespace install mode,
    and it does not require security context constraints
    """

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


def get_csv_from_name(csvs, csvName):
    """
    Returns a cluster service version from the csv name
    """
    for csv in csvs:
        if csv['metadata']['name'] == csvName:
            return csv

    return None


def push_package(package, version, target_namespace, oauth_token, basic_token, skip_push):
    '''
    Push package on disk into a target quay namespace.
    '''
    shortname = _pkg_shortname(package)

    if skip_push:
        logging.debug(f"Not pushing package {shortname} to namespace {target_namespace}")
        return

    # Don't try to push if the specific package version is already present in our target namespace
    target_releases = get_package_releases(f"{target_namespace}/{shortname}")
    if version in target_releases.keys():
        logging.info(f"Version {version} of {shortname} is already present in {target_namespace} namespace. Skipping...")
        return

    with open(f"{package}/{version}/{shortname}.tar.gz") as f:
        encoded_bundle = base64.b64encode(f.read())

    payload = {
        "blob": encoded_bundle,
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

    # If this is a new package namespace, make it publicly visible
    if target_releases.keys():
        set_repo_visibility(target_namespace, shortname, oauth_token)


def summarize(summary, out=sys.stdout):
    """Summarize prints a summary of results for human readability."""

    if not type(summary) == list:
        raise TypeError()
    if not summary:
        raise IndexError()


    report = []

    passing_count = len([i for i in summary if {key:value for (key, value) in i.items() if value["pass"]}])
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
        "\nValidation Summary\n" +
        "------------------\n" +
        f"{report_str}\n"
        "\n" +
        f"Passed: {passing_count}\n" +
        f"Failed: {len(summary) - passing_count}\n"
    )


if __name__ == "__main__":

    PARSER = argparse.ArgumentParser(description="A tool for curating application registry for use with OSDv4")
    PARSER.add_argument('--app-token', action="store", dest="basic_token",
                        type=str, help="Basic auth token for use with Quay's CNR API")
    PARSER.add_argument('--oauth-token', action="store", dest="oauth_token",
                        type=str, help="Oauth token for use with Quay's repository API")
    PARSER.add_argument('--cache', action="store_true", default=False, dest="use_cache",
                        help="Use local cache of operator packages")
    PARSER.add_argument('--skip-push', action="store_true", default=False, dest="skip_push",
                        help="Skip pushing validated packages to Quay.io")

    ARGS = PARSER.parse_args()

    logging.basicConfig(level=logging.INFO)

    SUMMARY = []

    for ns in SOURCE_NAMESPACES:
        for operator in list_operators(ns):
            release_dict = get_package_releases(operator)
            for release_version in release_dict:
                retrieve_package(operator, release_version, ARGS.use_cache)
                passed, info = validate_bundle(operator, release_version)
                SUMMARY.append({operator: {"version": release_version, "pass": passed, "tests": info}})
                if passed:
                    logging.info(f"{operator} version {release_version} is a valid operator for use with OSD")
                    push_package(operator, release_version, f"curated-{ns}", ARGS.oauth_token, ARGS.basic_token, ARGS.skip_push)
                else:
                    logging.info(f"{operator} version {release_version} FAILED VALIDATION for use with OSD")

    summarize(SUMMARY)
