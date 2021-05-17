import pandas as pd
from typing import Union
from IPython.display import display

def __type_dependent_drop(df: Union[pd.DataFrame, pd.Series]) -> Union[pd.DataFrame, pd.Series]:
    if type(df) is pd.Series:
        return df.dropna() 
    else: 
        return df.dropna(axis = 1, how = 'all')

def df_display(df: pd.DataFrame, index=None, seq_num=True) -> None:
    if df.empty:
        display(df)
    with pd.option_context('display.max_rows', 100,'display.max_columns', 200,'display.max_colwidth', 1000):        
        if index is None:
            display(__type_dependent_drop(df))
        elif seq_num:
            display(__type_dependent_drop(df).iloc[index])
        else:
            display(__type_dependent_drop(df).loc[index])