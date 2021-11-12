%%writefile app.py
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
import streamlit as st
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split,cross_validate

st.title("Malware Classification")
data = pd.read_csv("train_set_label.csv",header=0)
df = data.drop(["e_magic","e_crlc","e_res","e_res2"],axis=1)
labels = df["class"].values

df_new = df[["LoaderFlags","NumberOfSymbols","BaseOfCode","MajorImageVersion","MinorImageVersion" ,"CheckSum"]]


x_train,x_test,y_train,y_test = train_test_split(df_new,labels,test_size=0.2,random_state=101)
model = RandomForestClassifier(n_estimators=50)
model.fit(x_train,y_train)


xmin = np.min(df_new,axis=0)#min values in the datasets
xmax = np.max(df_new,axis=0)#max values in the datasets
LoaderFlags = st.slider('LoaderFlags',float(xmin[0]),float(xmax[0]))
NumberOfSymbols = st.slider('NumberOfSymbols',float(xmin[1]),float(xmax[1]))
BaseOfCode = st.slider('BaseOfCode',float(xmin[2]),float(xmax[2]))
MajorImageVersion= st.slider('MajorImageVersion',float(xmin[3]),float(xmax[3]))
MinorImageVersion= st.slider('MinorImageVersion',float(xmin[4]),float(xmax[4]))
CheckSum = st.slider('CheckSum',float(xmin[5]),float(xmax[5]))
y_pred = model.predict([[LoaderFlags,NumberOfSymbols,BaseOfCode,MajorImageVersion,MinorImageVersion,CheckSum]])
op = ["No Malware","Malware Detected"]
st.title(op[y_pred[0]])
