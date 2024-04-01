#  -------------------------------------------------------------------------
#  Copyright (c) Security Experts Community. All rights reserved.
#  Licensed under the MIT License. See License.txt in the project root for
#  license information.
#  --------------------------------------------------------------------------
"""MP SIEM events driver class."""
from datetime import datetime, timedelta
from typing import Any, Tuple, Union, Dict, Optional


import pandas as pd
from pandas import json_normalize
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 

from .driver_base import DriverBase, QuerySource
from ..._version import VERSION
from ...common.utility import export, check_kwargs
from ...common.exceptions import (
    MsticpyConnectionError,
    MsticpyNotConnectedError,
    MsticpyUserConfigError,
    MsticpyImportExtraError,
)
from ...common.provider_settings import get_provider_settings, ProviderSettings

try:
    from mpsiemlib.common import Creds, MPSIEMAuth, Settings
    from mpsiemlib.modules import EventsAPI
except ImportError as imp_err:
    raise MsticpyImportExtraError(
        "Cannot use this feature without mpsiemlib installed",
        title="Error importing mpsiemlib",
        extra="mpsiemlib",
    ) from imp_err

__version__ = VERSION
__author__ = "Anton Kutepov, Daniel Newman"   # inspired by Ashwin Patil Splunk Driver


MPSIEM_CONNECT_ARGS = {
    "host": "(string) The host name (the default is 'localhost').",
    "http_scheme": "('https' or 'http') The scheme for accessing the service "
    + "(the default is 'https').",
    "verify": "(Boolean) Enable (True) or disable (False) SSL verrification for "
    + "https connections. (optional, the default is True)",
    "username": "(string) The MaxPatrol SIEM account username, which is used to "
    + "authenticate the mpsiem instance.",
    "password": "(string) The password for the MaxPatrol SIEM account.",
}

@export
class MPSIEMEventsDriver(DriverBase):
    """Driver to connect and query events from MP SIEM."""

    _MPSIEM_REQD_ARGS = ["host", "username", "password"]
    _CONNECT_DEFAULTS: Dict[str, Any] = {
        'http_scheme': 'https',
        'verify': False
    }

    def __init__(self, **kwargs):
        """Instantiate MPSEIM Driver."""
        super().__init__()
        self.service = None
        self._connected = False        
        self._excluded_event_fields = [
            "_meta",
            "assets",
            "attacking_assets",
            "incident.aggregation.closed_behavior",
            "incident.aggregation.key",
            "incident.aggregation.time_window",
            "incident.aggregation.timeout",
            "incident.assigned_to_user_id",
            "incident.category",
            "incident.description",
            "incident.name",
            "incident.severity",
            "incident.severity_behavior",
            "subevents.time",
        ]
        self.logger  = None
        self._debug =  kwargs.pop('debug', False)
            
        self._loaded = True
        
    def connect(self, connection_str: str = None, **kwargs):
        """
        Connect to MaxPatrol SIEM via API.

        Parameters
        ----------
        connection_str : Optional[str], optional
            Connection string with MP SIEM connection parameters

        Other Parameters
        ----------------
        kwargs :
            Connection parameters can be supplied as keyword parameters.

        Notes
        -----
        Default configuration is read from the DataProviders/MPSEIM
        section of msticpyconfig.yaml, if available.

        """

        cs_dict = self._get_connect_args(connection_str, **kwargs)

        arg_dict = {
            key: val for key, val in cs_dict.items() if key in MPSIEM_CONNECT_ARGS
        }
        try:    
            creds = Creds({
                "core": {
                    "hostname": arg_dict["host"],
                    "login": arg_dict["username"],
                    "pass": arg_dict["password"],
                    "auth_type": 0,
                },
                "siem": {"hostname": arg_dict["host"]},
                "storage": {"hostname": arg_dict["host"]},
            })
            
            #TODO add to mpsiemlib this arguments                
            proxy=kwargs.pop("proxy", None),
            auth_api = MPSIEMAuth(creds=creds, settings=Settings())
            
            self.logger = auth_api.log
            log_level = kwargs.pop('loglevel', "DEBUG" if self._debug == True else "INFO")  
            self.logger.setLevel(log_level)
            
            self.service = EventsAPI(auth=auth_api, settings=Settings())
            
        except Exception as err:
            self.logger.error(f"Error connecting to MaxPatrol SIEM: {err}")
            raise MsticpyConnectionError(
                f"Error connecting to MaxPatrol SIEM: {err}",
                title="MaxPatrol SIEM connection",
            ) from err
        self.logger.info("MaxPatrol SIEM events driver connected to server")
        self._connected = True

    def query(
        self, query: str, query_source: Optional[QuerySource] = None, **kwargs
    ) -> Union[pd.DataFrame, Any]:
        """
        Execute MPSIEM query and retrieve results.

        Parameters
        ----------
        query : str
            PDQL query to execute via API
        query_source : QuerySource
            The query definition object

        Other Parameters
        ----------------
        kwargs :
            Are passed to mpsiemlib
            count=0 by default

        Returns
        -------
        Union[pd.DataFrame, Any]
            Query results in a dataframe.
            or query response if an error.

        """
        del query_source
        pd, raw = self.query_with_results(query=query, **kwargs)
        return pd
        
    def query_with_results(self, query: str, **kwargs) -> Tuple[pd.DataFrame, Any]:
        """
        Execute query string and return DataFrame of results.

        Parameters
        ----------
        query : str
            Query to execute against mpsiem instance.

        Returns
        -------
        Union[pd.DataFrame,Any]
            A DataFrame (if successful) or
            the underlying provider result if an error occurs.

        """
        if not self._connected:
            raise self._create_not_connected_err()
        
        recursive = kwargs.pop("recursive", False)
        
        # default to 500 query unless count is specified
        limit = kwargs.pop("limit", 500)
        offset = kwargs.pop("offset", 0) 
        
        start = kwargs.pop("time_start", datetime.now() - timedelta(hours=1))
        if isinstance(start, datetime):
            start = get_mpsiem_timestamp(start)
            
        end = kwargs.pop("time_end", get_mpsiem_timestamp(datetime.now()))
        if isinstance(end, datetime):
            end = get_mpsiem_timestamp(end)
        
        fields = [
            f["name"]
            for f in self.service.get_events_metadata()
            if f["name"] not in self._excluded_event_fields
        ]
        
        self.logger.debug("PDQL query with parameters: "+
                           f"filter: {query}, limit: {limit}, offset: {offset} ,recursive: {recursive}, "+
                           f"time_start: {start}, time_end: {end}")
        events = []
        if recursive:
            current_offset = offset
            something_left = True
            while something_left:
                reader = self.service.get_events_by_filter(
                    filter=query,
                    fields=fields,
                    time_from=start, 
                    time_to=end,
                    limit=limit,
                    offset=current_offset
                )
                something_left = len(reader) == limit
                current_offset += limit
                events.extend(reader)
                # for row in reader:
                    # events.append(row)
        else:
            events = self.service.get_events_by_filter(
                    filter=query,
                    fields=fields,
                    time_from=start, 
                    time_to=end,
                    limit=limit,
                    offset=offset
                )
            
        resp_rows = json_normalize(events)
        if resp_rows.empty:
            self.logger.warning("Warning: query did not return any results.")
            return pd.DataFrame(), None
        return resp_rows, events

    def _get_connect_args(
        self, connection_str: Optional[str], **kwargs
    ) -> Dict[str, Any]:
        """Check and consolidate connection parameters."""
        cs_dict: Dict[str, Any] = self._CONNECT_DEFAULTS
        # Fetch any config settings
        cs_dict.update(self._get_config_settings())
        # If a connection string - parse this and add to config
        if connection_str:
            cs_items = connection_str.split(";")
            cs_dict.update(
                {
                    cs_item.split("=")[0].strip(): cs_item.split("=")[1]
                    for cs_item in cs_items
                }
            )
        elif kwargs:
            # if connection args supplied as kwargs
            cs_dict.update(kwargs)
            check_kwargs(cs_dict, list(MPSIEM_CONNECT_ARGS.keys()))

        missing_args = set(self._MPSIEM_REQD_ARGS) - cs_dict.keys()
        if missing_args:
            self.logger.error(
                "One or more connection parameters missing for MaxPatrol SIEM driver" +
                ", ".join(missing_args) + 
                f"Required parameters are {', '.join(self._MPSIEM_REQD_ARGS)}" + 
                "All parameters:" + 
                ", ".join([f"{arg}: {desc}" for arg, desc in MPSIEM_CONNECT_ARGS.items()]))
            raise MsticpyUserConfigError(
                "One or more connection parameters missing for MPSIEM driver",
                ", ".join(missing_args),
                f"Required parameters are {', '.join(self._MPSIEM_REQD_ARGS)}",
                "All parameters:",
                *[f"{arg}: {desc}" for arg, desc in MPSIEM_CONNECT_ARGS.items()],
                title="MaxPatrol SIEM connection parameters missed",
            )
        return cs_dict

    # Read values from configuration
    @staticmethod
    def _get_config_settings() -> Dict[Any, Any]:
        """Get config from msticpyconfig."""
        data_provs = get_provider_settings(config_section="DataProviders")
        mpsiem_settings: Optional[ProviderSettings] = data_provs.get("MPSIEM")
        return getattr(mpsiem_settings, "Args", {})

    @staticmethod
    def _create_not_connected_err():
        return MsticpyNotConnectedError(
            "Please run the connect() method before running this method.",
            title="not connected to MPSIEM.",
        )

def timestamp_in_seconds(t: datetime) -> int:
    return int(round(t.timestamp()))

def timestamp_in_miliseconds(t: datetime) -> int:
    return int(round(t.timestamp()))*1000

def get_mpsiem_timestamp(t: datetime) -> int:
    return timestamp_in_seconds(t)