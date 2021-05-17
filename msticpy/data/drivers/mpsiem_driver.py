#  -------------------------------------------------------------------------
#  Copyright (c) Anton Kutepov. All rights reserved.
#  Licensed under the MIT License. See License.txt in the project root for
#  license information.
#  --------------------------------------------------------------------------
"""MPSIEM Driver class."""
from datetime import datetime, timedelta
from typing import Any, Tuple, Union, Dict, Iterable, Optional

import sys
import json
import logging

import pandas as pd
from pandas import json_normalize

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
    from mpsiem_api.base_functions.base import LoggerHandler
    from mpsiem_api.modules.siem_auth import SIEMAuth
    from mpsiem_api.params.params import AUTHParams
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 
except ImportError as imp_err:
    raise MsticpyImportExtraError(
        "Cannot use this feature without mpsiem_api installed",
        title="Error importing mpsiem_api",
        extra="mpsiem",
    ) from imp_err

__version__ = VERSION
__author__ = "Anton Kutepov"   # inspired by Ashwin Patil Splunk Driver


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

FORMATTER = logging.Formatter(
    "%(asctime)s - %(process)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def get_console_handler() -> logging.StreamHandler:
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler

class LoggerHandler():
    """Класс, создающий logger объект при наследовании"""
    logger = logging.getLogger(__name__)
    logger.setLevel("INFO")
    logger.addHandler(get_console_handler())
    logger.propagate = False


@export
class MPSIEMDriver(DriverBase, LoggerHandler):
    """Driver to connect and query from MPSIEM."""

    _MPSIEM_REQD_ARGS = ["host", "username", "password"]
    _CONNECT_DEFAULTS: Dict[str, Any] = {
        'http_scheme': 'https',
        'verify': False
    }
    _TIME_FORMAT = '"%Y-%m-%d %H:%M:%S.%6N"'

    def __init__(self, **kwargs):
        """Instantiate MPSEIM Driver."""
        super().__init__()
        self.service = None
        self._loaded = True
        self._connected = False
        self._debug = kwargs.get("debug", False)
        self.public_attribs = {
            "client": self.service,
            "saved_searches": self._saved_searches,
            "fired_alerts": self._fired_alerts,
        }
        self.formatters = {"datetime": self._format_datetime, "list": self._format_list}

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
            log_level = kwargs.pop('loglevel', 'INFO')
            self.logger.setLevel(log_level)
            mpsiem = SIEMAuth(
                arg_dict['http_scheme']+ '://' + arg_dict['host'],
                {
                    "username": arg_dict['username'], 
                    "password": arg_dict['password']
                },
                AUTHParams.LOCAL,
                proxy=kwargs.pop("proxy", None),
                logger=self.logger
            )
            self.service = mpsiem.connect(arg_dict['verify'])
        except Exception as err:
            self.logger.error(f"Error connecting to MaxPatrol SIEM: {err}")
            raise MsticpyConnectionError(
                f"Error connecting to MaxPatrol SIEM: {err}",
                title="MaxPatrol SIEM connection",
            ) from err
        self._connected = True
        self.logger.info("MaxPatrol SIEM driver connected to datastore")

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

        verify_opt = cs_dict.get("verify")
        if isinstance(verify_opt, str):
            cs_dict["verify"] = "true" in verify_opt.casefold()
        elif isinstance(verify_opt, bool):
            cs_dict["verify"] = verify_opt

        missing_args = set(self._MPSIEM_REQD_ARGS) - cs_dict.keys()
        if missing_args:
            self.logger.error(
                "One or more connection parameters missing for MaxPatrol SIEM connector " +
                ", ".join(missing_args) + 
                f"Required parameters are {', '.join(self._MPSIEM_REQD_ARGS)}" + 
                "All parameters:" + 
                ", ".join([f"{arg}: {desc}" for arg, desc in MPSIEM_CONNECT_ARGS.items()]))
            raise MsticpyUserConfigError(
                "One or more connection parameters missing for MPSIEM connector",
                ", ".join(missing_args),
                f"Required parameters are {', '.join(self._MPSIEM_REQD_ARGS)}",
                "All parameters:",
                *[f"{arg}: {desc}" for arg, desc in MPSIEM_CONNECT_ARGS.items()],
                title="no MaxPatrol SIEM connection parameters",
            )
        return cs_dict

    def query(
        self, query: str, query_source: QuerySource = None, **kwargs
    ) -> Union[pd.DataFrame, Any]:
        """
        Execute mpsiem query and retrieve results.

        Parameters
        ----------
        query : str
            MaxPatrol query to execute via API
        query_source : QuerySource
            The query definition object

        Other Parameters
        ----------------
        kwargs :
            Are passed to MPSIEM API wrapper
            count=0 by default

        Returns
        -------
        Union[pd.DataFrame, Any]
            Query results in a dataframe.
            or query response if an error.

        """
        del query_source
        if not self._connected:
            raise self._create_not_connected_err()
        # default to 500 query unless count is specified
        count = kwargs.pop("count", 500)
        recursive = kwargs.pop("recursive", False)
        start = kwargs.pop("time_start", datetime.now() - timedelta(hours=1))
        end = kwargs.pop("time_end", datetime.now())
        debug = kwargs.pop("debug", False)
        self.logger.debug("MPSIEM query with parameters: "+
                           f"filter: {query}, count: {count}, recursive: {recursive}, "+
                           f"time_start: {start}, time_end: {end}, debug: {debug}")
        reader = self.service.get_events(
            time_start=start, 
            time_end=end, 
            filter=query, 
            limit=count, 
            recursive=recursive,
            debug=debug
        )
        
        resp_rows = pd.DataFrame()
        for row in reader:
            data_df = row.event_data
            data_df = json_normalize(data_df)
            resp_rows = resp_rows.append(data_df)
        if resp_rows.empty:
            self.logger.warning("Warning: query did not return any results.")
            return pd.DataFrame()
        return resp_rows

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

    @property
    def service_queries(self) -> Tuple[Dict[str, str], str]:
        """
        Return dynamic queries available on connection to service.

        Returns
        -------
        Tuple[Dict[str, str], str]
            Dictionary of query_name, query_text.
            Name of container to add queries to.

        """
        if not self.connected:
            raise self._create_not_connected_err()
        if hasattr(self.service, "saved_searches") and self.service.saved_searches:
            queries = {
                search.name.strip().replace(" ", "_"): f"search {search['search']}"
                for search in self.service.saved_searches
            }
            return queries, "SavedSearches"
        return {}, "SavedSearches"

    @property
    def driver_queries(self) -> Iterable[Dict[str, Any]]:
        """
        Return dynamic queries available on connection to service.

        Returns
        -------
        Iterable[Dict[str, Any]]
            List of queries with properties: "name", "query", "container"
            and (optionally) "description"

        Raises
        ------
        MsticpyNotConnectedError
            If called before driver is connected.

        """
        if not self.connected:
            raise self._create_not_connected_err()
        if hasattr(self.service, "saved_searches") and self.service.saved_searches:
            return [
                {
                    "name": search.name.strip().replace(" ", "_"),
                    "query": f"search {search['search']}",
                    "query_paths": "SavedSearches",
                    "description": "",
                }
                for search in self.service.saved_searches
            ]
        return []

    @property
    def _saved_searches(self) -> Union[pd.DataFrame, Any]:
        """
        Return list of saved searches in dataframe.

        Returns
        -------
        pd.DataFrame
            Dataframe with list of saved searches with name and query columns.

        """
        if self.connected:
            return self._get_saved_searches()
        return None

    def _get_saved_searches(self) -> Union[pd.DataFrame, Any]:
        """
        Return list of saved searches in dataframe.

        Returns
        -------
        pd.DataFrame
            Dataframe with list of saved searches with name and query columns.

        """
        if not self.connected:
            raise self._create_not_connected_err()
        savedsearches = self.service.saved_searches

        out_df = pd.DataFrame(columns=["name", "query"])

        namelist = []
        querylist = []
        for savedsearch in savedsearches:
            namelist.append(savedsearch.name.replace(" ", "_"))
            querylist.append(savedsearch["search"])
        out_df["name"] = namelist
        out_df["query"] = querylist

        return out_df

    @property
    def _fired_alerts(self) -> Union[pd.DataFrame, Any]:
        """
        Return list of fired alerts in dataframe.

        Returns
        -------
        pd.DataFrame
            Dataframe with list of fired alerts with alert name and count columns.

        """
        if self.connected:
            return self._get_fired_alerts()
        return None

    def _get_fired_alerts(self) -> Union[pd.DataFrame, Any]:
        """
        Return list of fired alerts in dataframe.

        Returns
        -------
        pd.DataFrame
            Dataframe with list of fired alerts with alert name and count columns.

        """
        if not self.connected:
            raise self._create_not_connected_err()
        firedalerts = self.service.fired_alerts

        out_df = pd.DataFrame(columns=["name", "count"])

        alert_names = []
        alert_counts = []
        for alert in firedalerts:
            alert_names.append(alert.name)
            alert_counts.append(alert.count)
        out_df["name"] = alert_names
        out_df["count"] = alert_counts

        return out_df

    # Parameter Formatting methods
    @staticmethod
    def _format_datetime(date_time: datetime) -> str:
        """Return datetime-formatted string."""
        return f'"{date_time.isoformat(sep=" ")}"'

    @staticmethod
    def _format_list(param_list: Iterable[Any]) -> str:
        """Return formatted list parameter."""
        fmt_list = [f'"{item}"' for item in param_list]
        return ",".join(fmt_list)

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