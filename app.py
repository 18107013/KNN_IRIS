from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
import streamlit as st
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import train_test_split,cross_validate
import joblib

st.title("Malware Classification")
data = pd.read_csv("train_set_label.csv",header=0)
df = data.drop(["e_magic","e_crlc","e_res","e_res2"],axis=1)
labels = df["class"].values

x_vif = df[["e_lfanew","NumberOfSections","CreationYear","PointerToSymbolTable","NumberOfSymbols","Characteristics","MajorLinkerVersion",
            "MinorLinkerVersion","ImageBase","SectionAlignment","FileAlignment","MajorOperatingSystemVersion","MinorOperatingSystemVersion","MajorImageVersion",
           "MinorImageVersion","MajorSubsystemVersion","MinorSubsystemVersion","SizeOfHeaders","CheckSum","Subsystem","DllCharacteristics","SizeOfStackReserve","SizeOfStackCommit",
            "SizeOfHeapReserve","SizeOfHeapCommit","LoaderFlags"]]
model = joblib.load("malware_detection_TF")



xmin = np.min(x_vif,axis=0)#min values in the datasets
xmax = np.max(x_vif,axis=0)#max values in the datasets
e_lfanew = st.number_input('e_lfanew',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
NumberOfSections = st.number_input('NumberOfSections',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
CreationYear = st.number_input('CreationYear',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
PointerToSymbolTable = st.number_input('PointerToSymbolTable',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
NumberOfSymbols = st.number_input('NumberOfSymbols',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
Characteristics = st.number_input('Characteristics',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
MajorLinkerVersion = st.number_input('MajorLinkerVersion',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
MinorLinkerVersion = st.number_input('MinorLinkerVersion',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
ImageBase = st.number_input('ImageBase',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
SectionAlignment = st.number_input('SectionAlignment',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
FileAlignment = st.number_input('FileAlignment',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
MajorOperatingSystemVersion = st.number_input('"MajorOperatingSystemVersion',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
MinorOperatingSystemVersion = st.number_input('MinorOperatingSystemVersion',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
MajorImageVersion= st.number_input('MajorImageVersion',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
MinorImageVersion= st.number_input('MinorImageVersion',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
MajorSubsystemVersion= st.number_input('MajorSubsystemVersion',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
MinorSubsystemVersion= st.number_input('MinorSubsystemVersion',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
SizeOfHeaders= st.number_input('SizeOfHeaders',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
CheckSum = st.number_input('CheckSum',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
Subsystem = st.number_input('Subsystem',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
DllCharacteristics = st.number_input('DllCharacteristics',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
SizeOfStackReserve= st.number_input('SizeOfStackReserve',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
SizeOfStackCommit= st.number_input('SizeOfStackCommit',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
SizeOfHeapReserve= st.number_input('SizeOfStackReserve',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
SizeOfHeapCommit= st.number_input('SizeOfStackReserve',min_value=xmin[0],max_value=xmax[0],value=50,step=1)
LoaderFlags = st.number_input('LoaderFlags',min_value=xmin[0],max_value=xmax[0],value=50,step=1)

#MinorImageVersion= st.slider('MinorImageVersion',float(xmin[4]),float(xmax[4]))
y_pred = model.predict([[e_lfanew,NumberOfSections,CreationYear,PointerToSymbolTable,NumberOfSymbols,Characteristics,MajorLinkerVersion,
            MinorLinkerVersion,ImageBase,SectionAlignment,FileAlignment,MajorOperatingSystemVersion,MinorOperatingSystemVersion,MajorImageVersion,
           MinorImageVersion,MajorSubsystemVersion,MinorSubsystemVersion,SizeOfHeaders,CheckSum,Subsystem,DllCharacteristics,SizeOfStackReserve,SizeOfStackCommit,
            SizeOfHeapReserve,SizeOfHeapCommit,LoaderFlags]])
op = ["no Malware","Malware Detected"]
st.title(op[y_pred[0]])
