from .crowdstrike import crowdstrike_fdr_pipeline
from .crowdstrike import crowdstrike_falcon_pipeline

pipelines = {
    "crowdstrike_fdr": crowdstrike_fdr_pipeline,
    "crowdstrike_falcon": crowdstrike_falcon_pipeline,
}
