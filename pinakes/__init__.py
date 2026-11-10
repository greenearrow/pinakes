"""pinakes: a catalog of every file on every machine, and of who owns it."""

__version__ = "0.1.0.dev0"
BATCH_FORMAT = 2            # what the agent writes; 2: file records may carry extracted metadata ("meta")
BATCH_FORMATS = (1, 2)      # what the ingester accepts
