#!/usr/bin/env python
import gzip
import requests
import logging
import os
import json
import shutil
import tarfile
import yaml
import base64
import argparse

SOURCE_NAMESPACES= [
    "redhat-operators",
    "certified-operators",
    "community-operators"
]

WHITELISTED_PACKAGES = [
    "redhat-operators/cluster-logging",
    "redhat-operators/elasticsearch-operator",
    "redhat-operators/codeready-workspaces"
]

BLACKLISTED_PACKAGES = [
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
    r = requests.get(_url("packages/{}".format(package)))
    if r.ok:
        for release in r.json():
            releases[str(release['release'])] = str(release['content']['digest'])
    return releases

def list_operators(namespace):
    '''List the operators in the provided quay app registry namespace'''
    r = requests.get(_url("packages?namespace={}".format(namespace)))
    l = [ str(e['name']) for e in r.json() ]
    return l

def set_repo_visibility(namespace, package_shortname, oauth_token, public=True,):
    '''Set the visibility of the specified app registry in Quay.'''
    s = requests.sessions.Session()

    visibility = "public" if public else "private"

    logging.info("Setting visibility of {}/{} to {}".format(
        namespace,
        package_shortname,
        "public" if public else "private"
    ))
    try:
        r = s.post(
            _repo_url("repository/{}/{}/changevisibility".format(namespace, package_shortname)),
            json = {"visibility": visibility },
            headers = _quay_headers("Bearer {}".format(oauth_token))
        )
        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        logging.error("Failed to set visibility of {}/{}. HTTP Error: {}".format(
            namespace, package_shortname, errh))
    except requests.exceptions.ConnectionError as errc:
        logging.error("Failed to set visibility of {}/{}. Connection Error: {}".format(
            namespace, package_shortname, errc))
    except requests.exceptions.Timeout as errt:
        logging.error("Failed to set visibility of {}/{}. Timeout Error: {}".format(
            namespace, package_shortname, errt))

def retrieve_package(package, version, use_cache):
    '''Downloads an operator's package from quay'''
    if use_cache:
        logging.debug("Using local cache for package {}  version {} ".format(package, version))
        return

    logging.info("Downloading package {}  version {} ".format(package, version))
    r = requests.get(_url("packages/{}".format(package)))
    digest = [ str(i['content']['digest']) for i in r.json() if i['release'] == version][0]
    r = requests.get(_url("packages/{}/blobs/sha256/{}".format(package, digest)), stream=True)
    outfile_path = "{}/{}/{}.tar.gz".format(package, version, _pkg_shortname(package))
    
    if not os.path.exists(os.path.dirname(outfile_path)):
        os.makedirs(os.path.dirname(outfile_path))

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

    logging.info("Validating bundle for {} version {}".format(package, version))

    shortname = _pkg_shortname(package)

    # Any package in our whitelist is valid, regardless of other heuristics
    if package in WHITELISTED_PACKAGES:
        logging.info("[PASS] {} version {} is whitelisted".format(package, version))
        tests["is in allowed list"] = True
        return True, tests

    # Any package in our blacklist is invalid; skip further processing
    if package in BLACKLISTED_PACKAGES:
        logging.info("[FAIL] {} version {} is blacklisted".format(package, version))
        tests["is in denied list"] = False
        return False, tests
    
    with tarfile.open("{}/{}/{}.tar.gz".format(package, version, shortname)) as t:
        try:
            bf = t.extractfile([i for i in t if os.path.split(i.name)[-1] == "bundle.yaml"][0])
            tests["bundle.yaml must be present"] = True
        except IndexError:
            # Cannot perform tests; skip further processing
            logging.warn("[FAIL] Cannot validate {} version {}: 'bundle.yaml' not present in package".format(package, version))
            tests["bundle.yaml must be present"] = False
            return False, tests
        except KeyError:
            # Cannot perform tests; skip further processing
            logging.warn("[FAIL] Cannot validate {} version {}: 'bundle.yaml' not present in package".format(package, version))
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
        if len(packages) == 0:
            tests[packKey] = False
            return False, tests
        
        # The package might have multiple channels, loop thru them
        for channel in packages[0]['channels']:
            goodCSVs = []
            channelKey = "Curated channel: {}".format(channel['name'])
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

            latestBundleKey = "CSV {} curated".format(latestCSV['metadata']['name'])
            tests[latestBundleKey] = True
            
            goodCSVs.append(latestCSV)

            replacesCSVName = latestCSV['spec'].get('replaces')
            while replacesCSVName:
                nextCSV = get_csv_from_name(csvs, replacesCSVName)
                nextCSVPass, nextCSVTests = validate_csv(package, version, nextCSV)

                if not nextCSVPass:
                    # If this CSV does not pass curation, we truncate the bundle
                    # But we do not reject the entire bundle
                    nextCSVRejKey = "CSV {} rejected, truncating bundle here".format(replacesCSVName)
                    tests[nextCSVRejKey] = True
                    truncatedBundle = True
                    break
                else:
                    goodCSVs.append(nextCSV)
                    nextCSVPassKey = "CSV {} curated".format(replacesCSVName)
                    tests[nextCSVPassKey] = True
                    # Refresh the pointer to the 'replaces' tag
                    replacesCSVName = nextCSV.get('replaces')

            csvsByChannel[channel['name']] = goodCSVs 
            tests[channelKey] = True

        # If the bundle was truncated we need to regen the bundle file and links
        if truncatedBundle:
            csvs = []
            # For every channel, carry over the curated CSVs, and reset the 'replaces' field for the last one
            for channel in csvsByChannel:
                channelCSVs = csvsByChannel[channel]

                channelCSVs[-1]['spec'].pop('replaces', None)
                csvs += channelCSVs

            # Override CSVs in the original bundle
            by['data']['clusterServiceVersions'] = csvs
            by['data']['customResourceDefinitions'] = customResourceDefinitions
            by['data']['packages'] = packages

            bundle_filename = "bundle.yaml"
            bundle_file = os.path.join(package, version, bundle_filename)
            with open(bundle_file, 'w') as outfile:
                yaml.dump(by, outfile)

            # Create tar.gz file, forcing the bundle file to sit in the root of the tar vol
            with tarfile.open("{}/{}/{}.tar.gz".format(package, version, shortname), "w:gz") as tar_handle:
                tar_handle.add(bundle_file, arcname=bundle_filename)

    # If all of the values for dict "tests" are True, return True
    # otherwise return False (operator validation has failed!)
    result = True if all(tests.values()) else False
    return result, tests



def validate_csv(package, version, csv):

    tests = {}
    # Cluster Permissions aren't allowed
    cpKey = "CSV must not include clusterPermissions"
    tests[cpKey] = True
    if csv['spec']['install']['spec'].has_key('clusterPermissions'):
        logging.info("[FAIL] {} version {} requires clusterPermissions".format(package, version))
        tests[cpKey] = False
    # Using SCCs isn't allowed
    sccKey = "CSV must not grant SecurityContextConstraints permissions"
    tests[sccKey] = True
    if csv['spec']['install']['spec'].has_key('permissions'):
        for rules in csv['spec']['install']['spec']['permissions']:
            for i in rules['rules']:
                if ("security.openshift.io" in i['apiGroups'] and 
                    "use" in i['verbs'] and
                    "securitycontextconstraints" in i['resources']):
                    logging.info("[FAIL] {} version {} requires security context constraints".format(package, version))
                    tests[sccKey] = False
    # installMode == MultiNamespace is not allowed
    multiNsKey = "CSV must not require MultiNamespace installMode"
    tests[multiNsKey] = True
    for im in csv['spec']['installModes']:
        if im['type'] == "MultiNamespace" and im['supported'] is True:
            logging.info("[FAIL] {} version {} supports multi-namespace install mode".format(package, version))
            tests[multiNsKey] = False
    
    result = True if all(tests.values()) else False
    return result, tests

def get_csv_from_name(csvs, csvName):
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
        logging.debug("Not pushing package {} to namespace {}".format(target_namespace, shortname))
        return

    # Don't try to push if the specific package version is already present in our target namespace
    target_releases = get_package_releases("{}/{}".format(target_namespace, shortname))
    if version in target_releases.keys():
        logging.info("Version {} of {} is already present in {} namespace. Skipping...".format(version, shortname, target_namespace))
        return

    with open("{}/{}/{}.tar.gz".format(package, version, shortname)) as f:
        encoded_bundle = base64.b64encode(f.read())
    
    payload = {
        "blob": encoded_bundle,
        "release": version,
        "media_type": "helm"
    }

    try:
        logging.info("Pushing {} to the {} namespace".format(shortname, target_namespace))
        r = requests.post(_url("packages/{}/{}".format(target_namespace, shortname)), data=json.dumps(payload), headers=_quay_headers(basic_token))
        r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        if r.status_code == 409:
            logging.info("Version {} of {} is already present in {} namespace. Skipping...".format(version, shortname, target_namespace))
        else:
            logging.error("Failed to upload {} to {} namespace. HTTP Error: {}".format(
                shortname, target_namespace, errh))
    except requests.exceptions.ConnectionError as errc:
        logging.error("Failed to upload {} to {} namespace. Connection Error: {}".format(
            shortname, target_namespace, errc))
    except requests.exceptions.Timeout as errt:
        logging.error("Failed to upload {} to {} namespace. Timeout Error: {}".format(
            shortname, target_namespace, errt))

    # If this is a new package namespace, make it publicly visible 
    if len(target_releases.keys()) == 0:
        set_repo_visibility(target_namespace, shortname, oauth_token)


def summarize(summary):
    """Summarize prints a summary of results for human readability."""
    print("")
    print("Validation Summary")
    print("------------------")
    for i in summary:
       for operator, info in i.iteritems():
            print("{} {} version {}".format("[PASS]" if info["pass"] else "[FAIL]", operator, info["version"]))
            for name, result in info["tests"].iteritems():
                print("    {} {}".format("[PASS]" if result else "[FAIL]", name))
            print("")

    passed =  [i for i in summary if { key:value for (key,value) in i.items() if value["pass"] }]
    print("Passed: {}".format(len(passed)))
    print("Failed: {}".format(len(summary) - len(passed)))
    print("")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="A tool for curating application registry for use with OSDv4")
    parser.add_argument('--app-token', action="store", dest="basic_token",
                        help="Basic auth token for use with Quay's CNR API")
    parser.add_argument('--oauth-token', action="store", dest="oauth_token",
                        help="Oauth token for use with Quay's repository API")
    parser.add_argument('--cache', action="store_true", default=False, dest="use_cache",
                        help="Use local cache of operator packages")
    parser.add_argument('--skip-push', action="store_true", default=False, dest="skip_push",
                        help="Skip pushing validated packages to Quay.io")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    summary = []

    for ns in SOURCE_NAMESPACES:
        for op in list_operators(ns):
            releases = get_package_releases(op)
            for release in releases:
                retrieve_package(op, release, args.use_cache)
                passed, info = validate_bundle(op, release)
                summary.append({op: {"version": release, "pass": passed, "tests": info}})
                if passed:
                    logging.info("{} version {} is a valid operator for use with OSD".format(op, release))
                    push_package(op, release, "curated-{}".format(ns), args.oauth_token, args.basic_token, args.skip_push)
                else:
                    logging.info("{} version {} FAILED VALIDATION for use with OSD".format(op, release))

    summarize(summary)
