#!/bin/bash

# Comprobar si se proporcionaron suficientes argumentos
if [ $# -ne 2 ]; then
    echo "Usage: $0 <podname> <namespace>"
    exit 1
fi

podname="$1"
namespace="$2"

# Establecer el túnel SSH utilizando kubectl port-forward
kubectl port-forward -n $namespace $podname 2222:22