from pkg_resources import DistributionNotFound, get_distribution

try:
    __version__ = get_distribution("hikconnect").version
except DistributionNotFound:
    __version__ = "(local)"
