import pandas as pd
from typing import List, Union


def valid_config(config: dict) -> bool:
    # expecting condition section
    # if have no condition, then '*' must be present as value
    if 'conditions' not in config:
        return False
    if 'mapping' not in config:  # expecting mapping section
        return False    
    for mapping_entry in config['mapping']:        
        if type(config['mapping'][mapping_entry]) not in [str, list]: # value must be a string
            return False
    return True


def __df_filter(result: pd.DataFrame, conditions: dict):
    current_cond_result = result.copy()
    for condition in conditions:
        if condition not in current_cond_result.columns:
            return pd.DataFrame()  # we expect that this column presents in our dataframe   
        value = conditions[condition]
        if type(value) in [str, int, type(None)]:                    
            if value == 'not null':                               
                null_filter = current_cond_result[condition].isna()
                current_cond_result = current_cond_result[~null_filter]               
            elif value is None:
                na_value_filter = current_cond_result[condition].isna()
                current_cond_result = current_cond_result[na_value_filter]
            else:
                value_filter = current_cond_result[condition] == value
                current_cond_result = current_cond_result[value_filter]
        elif type(value) == list:
            tmp = pd.DataFrame()
            for list_entry in value:
                value_filter = current_cond_result[condition] == list_entry
                tmp = tmp.append(current_cond_result[value_filter], ignore_index=True)
            current_cond_result = tmp
        else:
            raise Exception("Unexpected condition value format")
    return current_cond_result


def df_filter(df: Union[pd.DataFrame, pd.Series], conditions: List[dict]) -> Union[pd.DataFrame, pd.Series]:
    result = df.copy()
    current_cond_result = pd.DataFrame()
    if type(conditions) is str and conditions == '*':
        return result    
    if type(conditions) == dict:
        current_cond_result = __df_filter(result, conditions)
    if type(conditions) == list:
        current_cond_result = pd.DataFrame()
        for condition in conditions:      
            current_cond_result = current_cond_result.append(__df_filter(result, condition), ignore_index=True)
    return current_cond_result


def map_fields(df: pd.DataFrame, mapping: dict, save_original=False) -> pd.DataFrame:
    simple_mapping = {k: v for k, v in mapping.items() if type(v) != list}
    if save_original:
        for key in simple_mapping:
            value = simple_mapping[key]
            df[value] = df[key]
    else:
        df.rename(columns = simple_mapping, inplace=True)
    multivalue_mapping = {k: v for k, v in mapping.items() if type(v) == list}
    for key in multivalue_mapping:
        if key not in df.columns:
            continue
        values = multivalue_mapping[key]
        for value in values:            
            df[value] = df[key]
        if not save_original:
            del df[key]
    return df


def prepare_object(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    if not valid_config(config):
        return pd.DataFrame()
    filtered = df_filter(df, config['conditions'])
    if filtered.empty:
        return filtered
    for key in config['extensions']:
        filtered[key] = config['extensions'][key]
    return map_fields(filtered, config['mapping']).applymap(str).drop_duplicates()
