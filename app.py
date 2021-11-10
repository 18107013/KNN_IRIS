from sklearn.datasets import load_iris #load_datasets

from sklearn.neighbors import KNeighborsClassifier
import streamlit as st
import numpy as np
st.title("Iris Flower Classification")
var = load_iris()
x = var.data
y = var.target
model = KNeighborsClassifier(n_neighbors=13,metric="euclidean")
model.fit(x,y)
xmin = np.min(x,axis=0)#min values in the datasets
xmax = np.max(x,axis=0)#max values in the datasets
sepal_length = st.slider('Sepal Length',float(xmin[0]),float(xmax[0]))
sepal_width = st.slider('Sepal width',float(xmin[1]),float(xmax[1]))
petal_length = st.slider('Petal Length',float(xmin[2]),float(xmax[2]))
petal_width = st.slider('Petal width',float(xmin[3]),float(xmax[3]))
y_pred = model.predict([[sepal_length,sepal_width,petal_length,petal_width]])
op = ['Iris-setosa', 'Iris-versicolor', 'Iris-virginica']
st.title(op[y_pred[0]]) #to obtain value in single dimension
