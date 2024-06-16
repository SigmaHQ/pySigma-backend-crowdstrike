from .logscale import LogScaleBackend

backends = {  # Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and expose them with the identifier.
    "CrowdStrike Logscale": LogScaleBackend,
}
