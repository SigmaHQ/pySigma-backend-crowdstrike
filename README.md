# pySigma CrowdStrike Processing Pipeline

This package provides a processing pipeline for CrowdStrike events. It was mainly written for Falcon Data Replicator data but Splunk queries should also work in the CrowdStrike Splunk.

It provides the package `sigma.pipeline.crowdstrike` with the `crowdstrike_fdr_pipeline` function that returns a ProcessingPipeline object.

Currently the pipeline adds support for the following event types (Sigma logsource category to event_simpleName mapping):

* process_creation: ProcessRollup2
    * Only rules with references to the file name of the parent image are supported because CrowdStrike ProcessRollup2 events only contain the file name.
* network_connection: NetworkConnectionIP4 or NetworkReceiveAcceptIP4 (depending on Initiated field value)
    * events that refer to process image names are not supported because this information is not available in CrowdStrike network connection events, just a process id reference.

Not supported because the FDR events lack information required by Sigma rules:

* create_remote_thread: event lack information required by most rules. No process details, only reference.

This backend is currently maintained by:

* [Thomas Patzke](https://github.com/thomaspatzke/)