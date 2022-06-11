# authentication-rest-service

This is the Authentication rest service.  It is used internally by the 
user-rest-service during user-signup and also can be used for authentication
using username/password and api-key to generate a JWT.

## Run locally

```
mvn spring-boot:run  -Dspring-boot.run.arguments="--POSTGRES_USERNAME=dummy \
                      --POSTGRES_PASSWORD=dummy \
                      --POSTGRES_DBNAME=authentication \
                      --POSTGRES_SERVICE=localhost:5432"
```
 
 
## Build Docker image

Build docker image using included Dockerfile.


`docker build -t imageregistry/project-rest-service:1.0 .` 

## Push Docker image to repository

`docker push imageregistry/project-rest-service:1.0`

## Deploy Docker image locally

`docker run -e POSTGRES_USERNAME=dummy \
 -e POSTGRES_PASSWORD=dummy -e POSTGRES_DBNAME=authentication \
  -e POSTGRES_SERVICE=localhost:5432 \
 --publish 8080:8080 imageregistry/project-rest-service:1.0`


## Installation on Kubernetes
Use my Helm chart here @ [sonam-helm-chart](https://github.com/sonamsamdupkhangsar/sonam-helm-chart):

```
helm install project-api sonam/mychart -f values.yaml --version 0.1.12 --namespace=yournamespace
```

##Instruction for port-forwarding database pod
```
export PGMASTER=$(kubectl get pods -o jsonpath={.items..metadata.name} -l application=spilo,cluster-name=project-minimal-cluster,spilo-role=master -n yournamesapce); 
echo $PGMASTER;
kubectl port-forward $PGMASTER 6432:5432 -n backend;
```

###Login to database instruction
```
export PGPASSWORD=$(kubectl get secret <SECRET_NAME> -o 'jsonpath={.data.password}' -n backend | base64 -d);
echo $PGPASSWORD;
export PGSSLMODE=require;
psql -U <USER> -d projectdb -h localhost -p 6432

```

`kubectl port-forward jwt-rest-service-mychart-1238293  8001:8080
`