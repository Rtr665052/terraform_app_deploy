#!/bin/sh

# start minikube and build image
minikube start
eval $(minikube docker-env)
docker build -t infrahash:latest .

# apply the manifest files
kubectl apply -f k8s/app-pvc.yaml
kubectl apply -f k8s/app-deploy.yaml
kubectl apply -f k8s/app-service.yaml

# verify pods are running
kubectl get pods
kubectl get svc

# get minikube ip
minikube ip
