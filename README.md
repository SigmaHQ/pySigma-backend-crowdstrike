# pySigma CrowdStrike Processing Pipeline

© 2024 The MITRE Corporation.
Approved for Public Release; Distribution Unlimited. Case Number 24-1824.

NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

@author Jason Slaughter jslaughter@mitre.org 
@author John Dombrowski JDOMBROWSKI@mitre.org 
@author Kaitlyn Laohoo klaohoo@mitre.org

NOTICE
This software was produced for the U. S. Government under Contract Number 70RSAT20D00000001 and Task Order 70RCSJ24FR0000016, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data—General – Alternate II (Dec 2007) and Alternate III (Dec 2007) (DEVIATION).

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.
For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.


![Tests](https://github.com/SigmaHQ/pySigma-pipeline-crowdstrike/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/thomaspatzke/46f41e1fcf5eaab808ff5742401ac42d/raw)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

This package provides a processing pipeline for CrowdStrike events. It was mainly written for Falcon Data Replicator data but Splunk queries should also work in the CrowdStrike Splunk.

It provides the package `sigma.pipeline.crowdstrike` with the `crowdstrike_fdr_pipeline` function that returns a ProcessingPipeline object.

Currently the pipeline adds support for the following event types (Sigma logsource category to event_simpleName mapping):

- process_creation: ProcessRollup2
  - Only rules with references to the file name of the parent image are supported because CrowdStrike ProcessRollup2 events only contain the file name.
- network_connection: NetworkConnectionIP4 or NetworkReceiveAcceptIP4 (depending on Initiated field value)
  - events that refer to process image names are not supported because this information is not available in CrowdStrike network connection events, just a process id reference.

Not supported because the FDR events lack information required by Sigma rules:

- create_remote_thread: event lack information required by most rules. No process details, only reference.

This backend is currently maintained by:

- [Thomas Patzke](https://github.com/thomaspatzke/)

## Getting Started

Make sure you have installed:
- Python 3
- pip
- pytest
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) (No need to clone the project)


Install the sigma splunk backend by running: 
```
sigma plugin install splunk
```

To install the pySigma CrowdStrike Processing Pipeline by running:
```
pip install crowdstrike_fdr_pipeline
```

The `crowdstrike_fdr_pipeline` must be installed before executing `pytest` to perform full test coverage testing. Follow the instructions in the sigma-cli [Getting Started](https://github.com/SigmaHQ/sigma-cli?tab=readme-ov-file#getting-started) to learn how to use the Sigma client in your local environment.


To run the pySigma CrowdStrike Processing Pipeline locally using Sigma-CLI, execute the following command:

```
sigma convert -p crowdstrike_fdr -t splunk -f default <rule.yml>
```

If you need to test your changes to the pipeline, modify the file located at `~\AppData\Local\Programs\Python\Python<version>\Lib\site-packages\sigma\pipelines\crowdstrike\crowdstrike.py` and run the `pytest` command from the command line.


To ensure that any local changes made to the pipeline have not broken the codebase, run the following command:

```
sigma convert -p crowdstrike_fdr -t splunk -f default <rule.yml>
```

## Change-Log

CB Lab team has made the following updates

- Updated mapping between Sigma process_creation and CS ProcessRollup2 / SyntheticProcessRollup2
- Created tests for new and updated mappings
- Updated the README.md with directions on testing for localhost development.

## TODO

- Create a docker image/enviroment on DockerHub for teams to pull down and use.
- Further document how this pipeline code works with the SigmaHQ repo. Possibly by pointing to a diagram or other README.md in another repo.
- Further implement missing fields.
