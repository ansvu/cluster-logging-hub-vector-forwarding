Table of Contents
=================

* [cluster-logging-hub-vector-forwarding](#cluster-logging-hub-vector-forwarding)
   * [Prerequisites](#prerequisites)
   * [OCP Logging stack architecture](#ocp-logging-stack-architecture)
   * [Logging Hub](#logging-hub)
      * [Deploy OpenShift Cluster-Logging and Elasticsearch Operators](#deploy-openshift-cluster-logging-and-elasticsearch-operators)
      * [Create Cluster Logging Custom Resource](#create-cluster-logging-custom-resource)
      * [Create Cluster Log Forwarder Custom Resource](#create-cluster-log-forwarder-custom-resource)
      * [Create External Elasticsearch Route to expose ES serivice for receiving logs from DU or CU clusters.](#create-external-elasticsearch-route-to-expose-es-serivice-for-receiving-logs-from-du-or-cu-clusters)
      * [Retrieve Elasticsearch Collector Secret For Client Log Forwarding](#retrieve-elasticsearch-collector-secret-for-client-log-forwarding)
   * [Logging Client](#logging-client)
      * [Deploy OpenShift Cluster-Logging Operator](#deploy-openshift-cluster-logging-operator)
      * [Create Cluster Logging Custom Resource](#create-cluster-logging-custom-resource-1)
      * [Create Cluster Log Forwarder Custom Resource](#create-cluster-log-forwarder-custom-resource-1)

# cluster-logging-hub-vector-forwarding
This repo will show how to use OpenShift Cluster-Logging Stack Vector as Forwarder instead of using Fluentd. From Client like DU/CU SNO/MMO Clusters can forward APP, AUDIT and INFRA Logs to centralize Logging-HUB to External Elasticsearch Server

## Prerequisites
In order to install and configure OpenShift Logging the following prerequisites must be met before starting the process.
Determining the supported Openshift Logging release according to the OCP version.

- OCP 4.12+
- OpenShift Logging subsystem v5.4+ but recommended to use v5.7+  
  Due to following features are enabled only on v5.7+ such as Syslog RFC3164, Syslog RFC5424 and HTTP  
- Centralize Hub-logging can be 1+0 or 3+0
- Check for Network requirements before starting, some specific ports must be accessible.
- Persistent storage is planned according to log size evaluation and retention time.
- FIPS disabled
- Comparison between Fluent and Vector features, please click [Here](https://docs.openshift.com/container-platform/4.12/logging/cluster-logging.html#cluster-logging-about-vector_cluster-logging)

**Note:** Vector does not support FIPS Enabled Clusters.  

[Vector's parameters](https://vector.dev/docs/about/concepts/)


## OCP Logging stack architecture
Click [here](https://cloud.redhat.com/blog/introduction-to-the-openshift-4-logging-stack) to see the introduction of OCP4 Logging Stack Architecture

## Logging Hub 
### Deploy OpenShift Cluster-Logging and Elasticsearch Operators

- Create CLO Namespace 
```yaml
cat 01_clo_hub_ns.yaml 
apiVersion: v1
kind: Namespace
metadata:
  name: openshift-operators-redhat 
  annotations:
    openshift.io/node-selector: ""
  labels:
    openshift.io/cluster-monitoring: "true"
```
```shellSession
$ oc apply -f 01_clo_hub_ns.yaml
```

- Create CLO OperatorGroup 
02_clo_hub_og.yaml: 
```yaml
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: cluster-logging
  namespace: openshift-logging
spec:
  targetNamespaces:
    - openshift-logging
```
```shellSession
$ oc apply -f 02_clo_hub_og.yaml
```
- Create CLO and Elasticsearch Subscriptions 
```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: cluster-logging
  namespace: openshift-logging 
spec:
  channel: "stable" 
  name: cluster-logging
  source: redhat-operators 
  sourceNamespace: openshift-marketplace
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: "elasticsearch-operator"
  namespace: "openshift-logging" 
spec:
  channel: "stable" 
  installPlanApproval: "Automatic" 
  source: "redhat-operators" 
  sourceNamespace: "openshift-marketplace"
  name: "elasticsearch-operator"
```
```shellSession
$ oc apply -f 03_clo_es_hub_subs.yaml
```
- Check CLO Operator POD Status 
```shellSession
$ oc get pod -n openshift-logging 
NAME                                            READY   STATUS      RESTARTS   AGE
cluster-logging-operator-594ddc54f9-5d995       1/1     Running     0          3d17h
```

### Create Cluster Logging Custom Resource
04_create_clo_hub_cr.yaml: 
```yaml
apiVersion: "logging.openshift.io/v1"
kind: ClusterLogging
metadata:
  name: instance
  namespace: openshift-logging
spec:
  collection:
    type: vector
  logStore:
    type: elasticsearch
    elasticsearch:
      nodeCount: 5
      storage:
        storageClassName: "ocs-storagecluster-cephfs"
        size: 200G
      resources: 
        limits:
          memory: "8Gi"
        requests:
          memory: "8Gi"
      proxy: 
        resources:
          limits:
            memory: 256Mi
          requests:
             memory: 256Mi
      redundancyPolicy: SingleRedundancy
    retentionPolicy: 
      application:
        maxAge: 7d
      infra:
        maxAge: 7d
      audit:
        maxAge: 7d
  managementState: Unmanaged
  visualization:
    type: kibana
    kibana:
      replicas: 1
```
```shellSession
$ oc apply -f 04_create_clo_hub_cr.yaml
```

### Create Cluster Log Forwarder Custom Resource
05_create_clf_hub_cr.yaml: 
```yaml
apiVersion: logging.openshift.io/v1
kind: ClusterLogForwarder
metadata:
  name: instance
  namespace: openshift-logging
spec:
  outputs:
    - name: internal-es
      type: elasticsearch
      secret:
        name: collector
      url: 'https://elasticsearch.openshift-logging.svc:9200'
  pipelines:
    - name: nokia-logs
      inputRefs:
        - application
        - infrastructure
        - audit
      outputRefs:
        - internal-es
      labels:
        node: hub-logging
```
```shellSession
$ oc apply -f 05_create_clf_hub_cr.yaml
$ oc -n openshift-logging get po
NAME                                            READY   STATUS      RESTARTS   AGE
cluster-logging-operator-594ddc54f9-5d995       1/1     Running     0          3d17h
collector-7xvq9                                 2/2     Running     0          3d18h
collector-8js2m                                 2/2     Running     0          3d18h
collector-cgp7w                                 2/2     Running     0          3d18h
collector-gzm4j                                 2/2     Running     0          3d18h
collector-nxvcl                                 2/2     Running     0          3d18h
elasticsearch-cd-ch5wrfo4-1-6d6f48f9b7-q6hk9    2/2     Running     0          3d18h
elasticsearch-cd-ch5wrfo4-2-6f8fddbcd4-srdgs    2/2     Running     0          3d18h
elasticsearch-cdm-uh1o9nsh-1-cdd975db4-rr9jz    2/2     Running     0          3d18h
elasticsearch-cdm-uh1o9nsh-2-79d74fcb77-79dj2   2/2     Running     0          3d18h
elasticsearch-cdm-uh1o9nsh-3-5bbff5947d-qqb62   2/2     Running     0          3d18h
elasticsearch-im-app-28139955-tplgl             0/1     Completed   0          39s
elasticsearch-im-audit-28139955-np2n9           0/1     Completed   0          39s
elasticsearch-im-infra-28139955-sx7q2           0/1     Completed   0          39s
kibana-85fc695d79-ssq2k                         2/2     Running     0          3d18h
```

### Create External Elasticsearch Route to expose ES serivice for receiving logs from DU or CU clusters.
06_create_external_es_route_hub.yaml: 
```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: elasticsearch-ext
  namespace: openshift-logging
spec:
  host:
  to:
    kind: Service
    name: elasticsearch
  tls:
    termination: passthrough
    insecureEdgeTerminationPolicy: Redirect
```
```shellSession
$ oc apply -f 06_create_external_es_route_hub.yaml
$ oc -n openshift-logging get route
NAME                HOST/PORT                                                                           PATH   SERVICES        PORT    TERMINATION            WILDCARD
elasticsearch-ext   elasticsearch-ext-openshift-logging.apps.abi.hubcluster-1.lab.eng.cert.redhat.com          elasticsearch   <all>   passthrough/Redirect   None
```

### Retrieve Elasticsearch Collector Secret For Client Log Forwarding
Export the collector TLS key and certificate. These key and certificate will be used on DU/CU clusters to forward logs to the Elasticsearch log store.

```shellSession
$ oc -n openshift-logging get secret > client_cert_secret.yaml
```

Note: The certificates and key are used from the ES collector secret, but the insecureSkipVerify flag must still be set to true for CU/DU clusters to forward logs to the Log Hub Store. It will be applied on the client cluster before create CLO CLF CR.


## Logging Client 
### Deploy OpenShift Cluster-Logging Operator
- Create CLO Namespace 
01_clo_client_ns.yaml: 
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: openshift-operators-redhat 
  annotations:
    openshift.io/node-selector: ""
  labels:
    openshift.io/cluster-monitoring: "true"
```
```shellSession
$ oc apply -f 01_clo_client_ns.yaml
```
- Create CLO OperatorGroup 
02_clo_client_og.yaml: 
```yaml
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: cluster-logging
  namespace: openshift-logging
spec:
  targetNamespaces:
    - openshift-logging
```
```shellSession
$ oc apply -f 02_clo_client_og.yaml
```

- Create CLO Subscription 
03_clo_client_subs.yaml: 
```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: cluster-logging
  namespace: openshift-logging 
spec:
  channel: "stable" 
  name: cluster-logging
  source: redhat-operators 
  sourceNamespace: openshift-marketplace
```
```shellSession
$ oc apply -f 03_clo_client_subs.yaml
```

- Check CLO Operator POD Status
```shellSession
$ oc -n openshift-logging get pod
NAME                                        READY   STATUS    RESTARTS       AGE
cluster-logging-operator-697669ccc8-kcn67   1/1     Running   6 (123m ago)   6d15h
```

### Create Cluster Logging Custom Resource
04_create_clo_client_cr.yaml:
```yaml
apiVersion: logging.openshift.io/v1
kind: ClusterLogging
metadata:
  name: instance
  namespace: openshift-logging
spec:
  collection:
    type: vector
```
```shellSession
$ oc apply -f 04_create_clo_client_cr.yaml
```

### Create Cluster Log Forwarder Custom Resource
- Create Collector Secret to communicate Elasticsearch External Endpoint 
05_create_client_collector_secret.yaml:  
```yaml
apiVersion: v1
data:
  ca-bundle.crt: xxxxxxxxxxxxxxxxxxxx
  tls.crt: xxxxxxxxxxxxxxxxxxxx
  tls.key: xxxxxxxxxxxxxxxxxxxx
kind: Secret
metadata:
  name: collector-hub
  namespace: openshift-logging
type: Opaque
```
```shellSession
$ oc apply -f 05_create_client_collector_secret.yaml
```

- Create CLF CR From Client 
06_create_clf_client_cr.yaml:
```yaml
apiVersion: "logging.openshift.io/v1"
kind: ClusterLogForwarder
metadata:
  name: instance 
  namespace: openshift-logging 
spec:
  outputs:
    - name: elasticsearch-external
      secret:
        name: sno-collector-secret
      tls:
        insecureSkipVerify: true
      type: elasticsearch
      url: >-
        https://elasticsearch-ext-openshift-logging.apps.abi.hubcluster-1.lab.eng.cert.redhat.com
  pipelines:
    - inputRefs:
        - audit
        - application
        - infrastructure
      labels:
        node: sno_nokiavf
      name: all-logs
      outputRefs:
        - elasticsearch-external
```
```shellSession
$ oc apply -f 05_create_clf_client_cr.yaml
```

- Check Collector POD Status 
```shellSession
$ oc -n openshift-logging get pod
NAME                                        READY   STATUS    RESTARTS       AGE
collector-8nnsn                             2/2     Running   0              3d18h
```
