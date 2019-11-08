# appregistry curator

The app registry curator is a tool that scans Quay.io app registries in order to vet operators for use with OSD v4.

## Requirements

The curator is a single python script that requires:

* requests
* PyYAML

## Credentials

In order to use this script, you'll need basic auth credentials for the Quay CNR API as well as an oauth token the Quay repository API. The basic auth token is required to push packages to the app registry, and the oauth token is required to make new packages publicly visible.

### Getting a basic auth token

The included script 'get-quay-token' will prompt for your Quay.io username and password and will return a basic auth token in this format:

{"token":"basic abcdefghi123456=="}

### Getting an oauth token

Navigate to quay.io/repository and select an organization to create a token under (eg. curated-redhat-operators). Select the "Applications" tab on the left, and then click the button "+ Create New Application".
Enter a name for your application (e.g. "appregistry-curator") and hit enter.
Click on the application name that appears.
Select the "Generate Token" tab on the left.
Click the "Administer Repositories" checkbox, then click "Generate Access Token".
Copy down the generated access token

Access Token: ZaaaAAAinsertvalidoauthtokenhereAAAaaaaz

This token will work across all organizations that your user has access to.

## Usage

You can launch the curator by providing it the credentials you just gathered:

./curator.py --app-token "basic abcdefghi123456==" --oauth-token "ZaaaAAAinsertvalidoauthtokenhereAAAaaaaz"

## Details

Currently, the script scans through every package on 3 app registry namespaces:

* redhat-operators
* certified-operators
* community-operators

It downloads and evaluates each version of each package in these registries. Currently an operator is deemed invalid for use with OSD v4 if:

* the package has no "bundle.yaml" file present
* the install spec requires "clusterPermissions"
* the install spec requires the use of SCCs
* the installMode spec supports "MultiNamespace"
* the package is in our blacklist.

An otherwise invalid operator can be added to the whitelist to have it be approved. Currently this whitelist includes "cluster-logging" and "elasticsearch-operator".

Operators that are deemed valid are then uploaded to their curated registry. Currently, the curated registries are:

* curated-redhat-operators
* curated-certified-operators
* curated-community-operators

## Running Unit Tests By Hand

Running unit tests by hand is just a matter of running:

```sh
# Python3 if python --version is not 3
python3 -m unittest test_curator.py

# otherwise:
python -m unittest test_curator.py
```

## Linting

Python linting can be done using Pylint.  Note that this isn't _currently_ completely passing the linter tests.

```sh
# Install pylint if it's not already
pip3 install --user pylint

pylint curator.py
pylint test_curator.py
```
