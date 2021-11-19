# Calico Cloud EKS Workshop
Kubernetes Security and Observability for EKS using Calico Cloud

# Creating an EKS cluster

**Goal:** Create EKS cluster.

This workshop uses EKS cluster with most of the default configuration settings. 
>To create an EKS cluster and tune the default settings, consider exploring [EKS Workshop](https://www.eksworkshop.com) materials.

We will create the cluster with the Calico CNI as there are no limitations on pods per node (unlike the AWS VPC CNI): <br/>
https://aws.amazon.com/blogs/opensource/networking-foundation-eks-aws-cni-calico/#:~:text=In%20contrast%2C%20Calico%20has%20no,be%20used%20across%20all%20nodes.

## Steps


Download and extract the latest release of eksctl with the following command
```
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
```
 
Move the extracted binary to /usr/local/bin.
```
sudo mv /tmp/eksctl /usr/local/bin
``` 

Test that your installation was successful with the following command
```
eksctl version
``` 

Download the vended kubectl binary for your cluster's Kubernetes version from Amazon S3
```
curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/kubectl
```

Check the SHA-256 sum for your downloaded binary
```
openssl sha1 -sha256 kubectl
```

Apply execute permissions to the binary
```
chmod +x ./kubectl
```

Create a $HOME/bin/kubectl and ensuring that $HOME/bin comes first in your $PATH
```
mkdir -p $HOME/bin && cp ./kubectl $HOME/bin/kubectl && export PATH=$PATH:$HOME/bin
```

Add $HOME/bin path to your shell initialization file so it's configured when opening shell
```
echo 'export PATH=$PATH:$HOME/bin' >> ~/.bashrc
```

After you install kubectl , you can verify its version with the following command
```
kubectl version --short --client
```

<img width="1403" alt="Screenshot 2021-07-06 at 10 18 44" src="https://user-images.githubusercontent.com/82048393/124575911-b83b4800-de43-11eb-8a4c-286bba2dda9e.png">


First, create an Amazon EKS cluster without any nodes
```
eksctl create cluster  --name tigera-workshop  --version 1.19  --with-oidc  --without-nodegroup
```

Delete the aws-node daemon set to disable AWS VPC networking for pods
```
kubectl delete daemonset -n kube-system aws-node
```

To configure the Calico CNI plugin, we must create an Install resource that has spec.cni.type
```
kubectl create -f https://docs.tigera.io/manifests/eks/custom-resources-calico-cni.yaml
```

Finally, add nodes to the cluster
```
eksctl create nodegroup --cluster tigera-workshop --node-type t3.xlarge  --nodes 3 --nodes-min 0 --nodes-max 3 --node-ami auto --max-pods-per-node 58
```

Alternatively, we can just create a cluster using the default AWS VPC CNI:

```
eksctl create cluster  --name tigera-workshop  --version 1.19  --with-oidc --node-type t3.xlarge  --nodes 3 --nodes-min 0 --nodes-max 3 --node-ami auto --max-pods-per-node 58
```

<img width="1779" alt="Screenshot 2021-07-06 at 10 23 41" src="https://user-images.githubusercontent.com/82048393/124576833-9b534480-de44-11eb-8d4d-b0ba63cb510b.png">


This bypasses the need to removing the cluster node group > removing the aws-node daemonset > installing the Calico CNI > and finally creating a supported node group for your cluster. 

>Please note: This might take 8-10 cycles/minutes for CloudFormation to finish cluster deployment:

<img width="1784" alt="Screenshot 2021-07-06 at 10 44 00" src="https://user-images.githubusercontent.com/82048393/124579606-30573d00-de47-11eb-8759-b13cccd95f51.png">





On completion, you can view your EKS cluster by running the below `eksctl` command:

```
eksctl get cluster tigera-workshop
```

<img width="854" alt="Screenshot 2021-07-06 at 10 51 05" src="https://user-images.githubusercontent.com/82048393/124580557-28e46380-de48-11eb-8a76-6e4461c77ffb.png">




# Module 3: Joining EKS cluster to Calico Cloud

**Goal:** Join EKS cluster to Calico Cloud management plane.

>In order to complete this module, you must have [Calico Cloud trial account](https://www.tigera.io/tigera-products/calico-cloud/).

<img width="1748" alt="Screenshot 2021-07-06 at 10 58 32" src="https://user-images.githubusercontent.com/82048393/124582160-abb9ee00-de49-11eb-9346-adcaceb7106c.png">

<img width="1422" alt="Screenshot 2021-07-06 at 10 59 04" src="https://user-images.githubusercontent.com/82048393/124582176-af4d7500-de49-11eb-9f56-b2681c856923.png">

## Steps

1. Join EKS cluster to Calico Cloud management plane.

    Use Calico Cloud install script provided in the welcome email for Calico Cloud trial account.

```
# script should look similar to this
curl https://installer.calicocloud.io/xxxxxx_yyyyyyy-saay-management_install.sh | bash
```

    Joining the cluster to Calico Cloud can take a few minutes. Wait for the installation script to finish before you proceed to the next step.

    You should see the output similar to this:

<img width="1086" alt="Screenshot 2021-07-06 at 11 03 08" src="https://user-images.githubusercontent.com/82048393/124582535-02272c80-de4a-11eb-92dc-12228d580542.png">


2. Configure log aggregation and flush intervals.

    ```
    kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFlushInterval":"10s"}}'
    kubectl patch felixconfiguration.p default -p '{"spec":{"dnsLogsFlushInterval":"10s"}}'
    kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
    ```
    
    <img width="1139" alt="Screenshot 2021-07-06 at 11 05 36" src="https://user-images.githubusercontent.com/82048393/124582712-2d118080-de4a-11eb-9897-73e06be11e43.png">


3. Configure Felix for log data collection.

    >[Felix](https://docs.tigera.io/reference/architecture/overview#felix) is one of Calico components that is responsible for configuring routes, ACLs, and anything else required on the host to provide desired connectivity for the endpoints on that host.

```
kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"policySyncPathPrefix":"/var/run/nodeagent","l7LogsFileEnabled":true}}'
```
    
    
 
# Module 4: Configuring demo applications

**Goal:** Deploy and configure demo applications.

## Steps

1. Deploy policy tiers.

    We are going to deploy some policies into policy tier to take advantage of hierarcical policy management.
    
```
cat << EOF > tiers.yaml
---
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: security
spec:
  order: 400

---
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: platform
spec:
  order: 500
EOF
```

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/calico-enterprise-eks-workshop/main/policies/tiers.yaml
```

<img width="532" alt="Screenshot 2021-07-06 at 11 10 10" src="https://user-images.githubusercontent.com/82048393/124583358-dd7f8480-de4a-11eb-9f29-33d76d295652.png">

<img width="1191" alt="Screenshot 2021-07-06 at 11 11 55" src="https://user-images.githubusercontent.com/82048393/124583481-fe47da00-de4a-11eb-8c48-178dcf1ecf1f.png">




This will add tiers `security` and `platform` to the Calico cluster.

2. Deploy base policy.

    In order to explicitly allow workloads to connect to the Kubernetes DNS component, we are going to implement a policy that controls such traffic.

```
cat << EOF > allow-kube-dns.yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: security.allow-kube-dns
spec:
  # requires security tier to exist
  tier: security
  order: 2000
  selector: all()
  types:
  - Egress
  egress:
  - action: Allow
    protocol: UDP
    source: {}
    destination:
      selector: "k8s-app == 'kube-dns'"
      ports:
      - '53'
  - action: Pass
    source: {}
    destination: {}
EOF    
```

Apply the file

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/calico-enterprise-eks-workshop/main/policies/allow-kube-dns.yaml
```
    
At this point, we have created our 1st network policy to allow traffic for Kube-DNS (based solely on label selection):

<img width="1194" alt="Screenshot 2021-07-06 at 11 16 58" src="https://user-images.githubusercontent.com/82048393/124584175-d7d66e80-de4b-11eb-83eb-75ff19dc304c.png">
    

3. Deploy demo applications.

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/dev/app.manifests.yaml
```

```
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
```

After running the above 3 commands, you should have the demo application up-and-running:

<img width="1363" alt="Screenshot 2021-07-06 at 11 14 47" src="https://user-images.githubusercontent.com/82048393/124583911-84642080-de4b-11eb-94ef-83cd89cef69b.png">




4. Deploy compliance reports.

    >The reports will be needed for one of a later lab.

```
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: daily-cis-results
  labels:
    deployment: production
spec:
  reportType: cis-benchmark
  schedule: 0 0 * * *
  cis:
    highThreshold: 100
    medThreshold: 50
    includeUnscoredTests: true
    numFailedTests: 5
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/40-compliance-reports/daily-cis-results.yaml
```

```
---
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: half-hour-inventory
spec:
  reportType: inventory
  schedule: '*/30 * * * *'

---
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: hourly-network-access
spec:
  reportType: network-access
  schedule: 0 * * * *

# uncomment policy-audit report if you configured audit logs for EKS cluster https://docs.tigera.io/compliance/compliance-reports/compliance-managed-cloud#enable-audit-logs-in-eks
# ---
# apiVersion: projectcalico.org/v3
# kind: GlobalReport
# metadata:
#   name: weekly-policy-audit
# spec:
#   reportType: policy-audit
#   schedule: 0 0 0 * *
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/40-compliance-reports/cluster-reports.yaml
```

5. Deploy global alerts.

    >The alerts will be explored later on in the workshop.

```
---
apiVersion: projectcalico.org/v3
kind: GlobalAlertTemplate
metadata:
  name: policy.globalnetworkset
spec:
  description: "Alerts on any changes to global network sets"
  summary: "[audit] [privileged access] change detected for ${objectRef.resource} ${objectRef.name}"
  severity: 100
  period: 5m
  lookback: 5m
  dataSet: audit
  # alert is triggered if CRUD operation executed against any globalnetworkset
  query: (verb=create OR verb=update OR verb=delete OR verb=patch) AND "objectRef.resource"=globalnetworksets
  aggregateBy: [objectRef.resource, objectRef.name]
  metric: count
  condition: gt
  threshold: 0

---
apiVersion: projectcalico.org/v3
kind: GlobalAlert
metadata:
  name: policy.globalnetworkset
spec:
  description: "Alerts on any changes to global network sets"
  summary: "[audit] [privileged access] change detected for ${objectRef.resource} ${objectRef.name}"
  severity: 100
  period: 1m
  lookback: 1m
  dataSet: audit
  # alert is triggered if CRUD operation executed against any globalnetworkset
  query: (verb=create OR verb=update OR verb=delete OR verb=patch) AND "objectRef.resource"=globalnetworksets
  aggregateBy: [objectRef.resource, objectRef.name]
  metric: count
  condition: gt
  threshold: 0
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/globalnetworkset.changed.yaml
```

```
---
apiVersion: projectcalico.org/v3
kind: GlobalAlertTemplate
metadata:
  name: dns.unsanctioned.access
spec:
  description: "Pod attempted to access restricted.com domain"
  summary: "[dns] pod ${client_namespace}/${client_name_aggr} attempted to access '${qname}'"
  severity: 100
  dataSet: dns
  period: 5m
  lookback: 5m
  query: '(qname = "www.restricted.com" OR qname = "restricted.com")'
  aggregateBy: [client_namespace, client_name_aggr, qname]
  metric: count
  condition: gt
  threshold: 0

---
apiVersion: projectcalico.org/v3
kind: GlobalAlert
metadata:
  name: dns.unsanctioned.access
spec:
  description: "Pod attempted to access google.com domain"
  summary: "[dns] pod ${client_namespace}/${client_name_aggr} attempted to access '${qname}'"
  severity: 100
  dataSet: dns
  period: 1m
  lookback: 1m
  query: '(qname = "www.google.com" OR qname = "google.com")'
  aggregateBy: [client_namespace, client_name_aggr, qname]
  metric: count
  condition: gt
  threshold: 0
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/unsanctioned.dns.access.yaml
```

```
---
apiVersion: projectcalico.org/v3
kind: GlobalAlertTemplate
metadata:
  name: network.lateral.access
spec:
  description: "Alerts when pods with a specific label (security=strict) accessed by other workloads from other namespaces"
  summary: "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} has accessed ${dest_namespace}/${dest_name_aggr} with label security=strict"
  severity: 100
  period: 5m
  lookback: 5m
  dataSet: flows
  query: '"dest_labels.labels"="security=strict" AND "dest_namespace"="secured_pod_namespace" AND "source_namespace"!="secured_pod_namespace" AND proto=tcp AND (("action"="allow" AND ("reporter"="dst" OR "reporter"="src")) OR ("action"="deny" AND "reporter"="src"))'
  aggregateBy: [source_namespace, source_name_aggr, dest_namespace, dest_name_aggr]
  field: num_flows
  metric: sum
  condition: gt
  threshold: 0

---
apiVersion: projectcalico.org/v3
kind: GlobalAlert
metadata:
  name: network.lateral.access
spec:
  description: "Alerts when pods with a specific label (security=strict) accessed by other workloads from other namespaces"
  summary: "[flows] [lateral movement] ${source_namespace}/${source_name_aggr} has accessed ${dest_namespace}/${dest_name_aggr} with label security=strict"
  severity: 100
  period: 1m
  lookback: 1m
  dataSet: flows
  query: '("dest_labels.labels"="security=strict" AND "dest_namespace"="dev") AND "source_namespace"!="dev" AND "proto"="tcp" AND (("action"="allow" AND ("reporter"="dst" OR "reporter"="src")) OR ("action"="deny" AND "reporter"="src"))'
  aggregateBy: [source_namespace, source_name_aggr, dest_namespace, dest_name_aggr]
  field: num_flows
  metric: sum
  condition: gt
  threshold: 0
```

```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/unsanctioned.lateral.access.yaml
```


For this section, we simply ran some `kubectl apply` commands in order to create our global alerts and scheduling compliance reports:

<img width="1575" alt="Screenshot 2021-07-06 at 11 20 13" src="https://user-images.githubusercontent.com/82048393/124584660-6a770d80-de4c-11eb-86cf-22ae241b1d16.png">




# Module 5: Using security controls

**Goal:** Leverage network policies to segment connections within Kubernetes cluster and prevent known bad actors from accessing the workloads.

## Steps

1. Test connectivity between application components and across application stacks.

    a. Test connectivity between workloads within each namespace.

    Test connectivity within dev namespace
    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://nginx-svc 2>/dev/null | grep -i http'
    ```
    Test connectivity within default namespace    
    ```
    kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI frontend 2>/dev/null | grep -i http'
    ```
    Test connectivity with product catalog service (work in progress)
    ```
    kubectl exec -it $(kubectl get po -l app=frontend -ojsonpath='{.items[0].metadata.name}') -c server -- sh -c 'nc -zv productcatalogservice 3550'
    ```
    
    <img width="1575" alt="Screenshot 2021-07-06 at 11 24 03" src="https://user-images.githubusercontent.com/82048393/124585014-cb064a80-de4c-11eb-8765-75be922604d0.png">


    b. Test connectivity across namespaces.

    Test connectivity from dev namespace to default namespace
```
kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://frontend.default 2>/dev/null | grep -i http'
```
   Test connectivity from default namespace to dev namespace
```
kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI http://nginx-svc.dev 2>/dev/null | grep -i http'
```
    
  <img width="1670" alt="Screenshot 2021-07-06 at 11 25 51" src="https://user-images.githubusercontent.com/82048393/124585186-f9842580-de4c-11eb-8826-5461957a779b.png">


  c. Test connectivity from each namespace to the Internet.

    
  Test connectivity from dev namespace to the Internet
```
kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://www.google.com 2>/dev/null | grep -i http'
```
    
   Test connectivity from default namespace to the Internet
 ```
 kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI www.google.com 2>/dev/null | grep -i http'
 ```

   <img width="1781" alt="Screenshot 2021-07-06 at 11 27 30" src="https://user-images.githubusercontent.com/82048393/124585470-394b0d00-de4d-11eb-843f-735f51198139.png">

   
    All of these tests should succeed if there are no policies in place to govern the traffic for `dev` and `default` namespaces.

2. Apply staged `default-deny` policy.

    >Staged `default-deny` policy is a good way of catching any traffic that is not explicitly allowed by a policy without explicitly blocking it.

```
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  order: 2000
  selector: "projectcalico.org/namespace in {'dev','default'}"
  types:
  - Ingress
  - Egress
```

Apply the below command

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/calico-enterprise-eks-workshop/main/policies/default-deny.yaml
```

The output should look something like this.. 
    <img width="1183" alt="Screenshot 2021-07-06 at 11 41 39" src="https://user-images.githubusercontent.com/82048393/124587103-29ccc380-de4f-11eb-8862-fa007fa55dec.png">

You should be able to view the potential affect of the staged `default-deny` policy if you navigate to the `Dashboard` view in the Enterprise Manager UI and look at the `Packets by Policy` histogram.
    
    
  <img width="928" alt="Screenshot 2021-07-06 at 11 42 48" src="https://user-images.githubusercontent.com/82048393/124587258-54b71780-de4f-11eb-9713-08c2d2d9d5af.png">


```
# make a request across namespaces and view Packets by Policy histogram
for i in {1..10}; do kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://frontend.default 2>/dev/null | grep -i http'; sleep 2; done
```

   >The staged policy does not affect the traffic directly but allows you to view the policy impact if it were to be enforced.

3. Apply network policies to control East-West traffic.

    Deploy dev policies
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/dev/policies.yaml
```
    
Deploy boutiqueshop policies
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/boutiqueshop/policies.yaml
```
    
 <img width="1308" alt="Screenshot 2021-07-06 at 11 44 39" src="https://user-images.githubusercontent.com/82048393/124587558-a790cf00-de4f-11eb-8a76-bf1e4395057e.png">

<img width="1185" alt="Screenshot 2021-07-06 at 11 46 21" src="https://user-images.githubusercontent.com/82048393/124587723-dc9d2180-de4f-11eb-939d-3e9ac6d958b9.png">


    Now as we have proper policies in place, we can enforce `default-deny` policy moving closer to zero-trust security approach. You can either enforced the already deployed staged `default-deny` policy using the `Policies Board` view in the Enterirpse Manager UI, or you can apply an enforcing `default-deny` policy manifest.

    
 After enforcing default-deny policy manifest
 
    ```
    kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/calico-enterprise-eks-workshop/main/policies/default-deny2.yaml
    ```
 
 You can delete staged default-deny policy
    ```
    kubectl delete -f https://raw.githubusercontent.com/n1g3ld0uglas/calico-enterprise-eks-workshop/main/policies/default-deny.yaml
    ```
    
   <img width="1365" alt="Screenshot 2021-07-06 at 11 50 18" src="https://user-images.githubusercontent.com/82048393/124588175-6c42d000-de50-11eb-8420-aadff8001c5b.png">



4. Test connectivity with policies in place.

    a. The only connections between the components within each namespaces should be allowed as configured by the policies.

    
    Test connectivity within dev namespace
    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://nginx-svc 2>/dev/null | grep -i http'
    ```

    Test connectivity within default namespace
    ```
    kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI frontend 2>/dev/null | grep -i http'
    ```

    b. The connections across `dev` and `default` namespaces should be blocked by the global `default-deny` policy.

    
    Test connectivity from dev namespace to default namespace
    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://frontend.default 2>/dev/null | grep -i http'
    ```
    
    Test connectivity from default namespace to dev namespace
    ```
    kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI http://nginx-svc.dev 2>/dev/null | grep -i http'
    ```
    
    <img width="1669" alt="Screenshot 2021-07-06 at 11 54 11" src="https://user-images.githubusercontent.com/82048393/124588665-f7bc6100-de50-11eb-9b49-d8354127c120.png">


    c. The connections to the Internet should be blocked by the configured policies.

    
    Test connectivity from dev namespace to the Internet
    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://www.google.com 2>/dev/null | grep -i http'
    ```
    Test connectivity from default namespace to the Internet
    ```
    kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI www.google.com 2>/dev/null | grep -i http'
    ```
    
    <img width="1669" alt="Screenshot 2021-07-06 at 11 56 22" src="https://user-images.githubusercontent.com/82048393/124588892-3fdb8380-de51-11eb-97fa-438ae1e0928d.png">


5. Protect workloads from known bad actors.

    Calico offers `GlobalThreatfeed` resource to prevent known bad actors from accessing Kubernetes pods.

    
    Deploy feodo tracker threatfeed
    ```
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/10-security-controls/feodotracker.threatfeed.yaml
    ```
    
    <img width="1771" alt="Screenshot 2021-07-06 at 13 34 36" src="https://user-images.githubusercontent.com/82048393/124600812-090c6a00-de5f-11eb-9650-a87791fa215a.png">

    
    Deploy network policy that uses the threatfeed
    ```
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/10-security-controls/feodo-block-policy.yaml
    ```
    
    
    

    Try to ping any of the IPs in from the feodo tracker list
    ```
    IP=$(kubectl get globalnetworkset threatfeed.feodo-tracker -ojson | jq .spec.nets[0] | sed -e 's/^"//' -e 's/"$//' -e 's/\/32//')
    ```
    
    Try pinging the IP address associated with the threat feed:
    ```
    kubectl -n dev exec -t centos -- sh -c "ping -c1 $IP"
    ```

# Module 6: Using egress access controls

**Goal:** Configure egress access for specific workloads.

## Steps

1. Test connectivity within the cluster and to the external endpoint.

    a. Test connectivity between `dev/centos` pod and `default/frontend` pod.

    ```
    # test connectivity from dev namespace to default namespace
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://frontend.default 2>/dev/null | grep -i http'
    ```

    b. Test connectivity from `dev/centos` to the external endpoint.

    ```
    # test connectivity from dev namespace to the Internet
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://www.google.com 2>/dev/null | grep -i http'
    ```

    The access should be denied as the policies configured in previous module do not allow it.

2. Implement egress policy to allow egress access from a workload in one namespace, e.g. `dev/centos`, to a service in another namespace, e.g. `default/frontend`.

    a. Deploy egress policy.

    ```
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/20-egress-access-controls/centos-to-frontend.yaml
    ```

    b. Test connectivity between `dev/centos` pod and `default/frontend` service.

    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://frontend.default 2>/dev/null | grep -i http'
    ```

    The access should be allowed once the egress policy is in place.
    
    <img width="1580" alt="Screenshot 2021-07-06 at 13 28 11" src="https://user-images.githubusercontent.com/82048393/124599900-18d77e80-de5e-11eb-944c-0a4c796bfc8a.png">


3. Implement DNS policy to allow the external endpoint access from a specific workload, e.g. `dev/centos`.

    a. Apply a policy to allow access to `api.twilio.com` endpoint using DNS rule.

    
    Deploy dns policy
    ```
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/20-egress-access-controls/dns-policy.yaml
    ```
    
    Test egress access to api.twilio.com
    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -skI https://api.twilio.com 2>/dev/null | grep -i http'
    ```
    Test egress access to www.google.com
    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -skI https://www.google.com 2>/dev/null | grep -i http'
    ```
    
    <img width="1579" alt="Screenshot 2021-07-06 at 13 30 36" src="https://user-images.githubusercontent.com/82048393/124600244-6ce26300-de5e-11eb-9956-89c47bf41b6f.png">


    Access to the `api.twilio.com` endpoint should be allowed by the DNS policy but not to any other external endpoints like `www.google.com` unless we modify the policy to include that domain name.

    b. Edit the policy to use a `NetworkSet` instead of inline DNS rule.


    Deploy network set
    ```    
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/20-egress-access-controls/netset.external-apis.yaml
    ``` 
    Deploy DNS policy using the network set
    ``` 
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/20-egress-access-controls/dns-policy.netset.yaml
    ```
    
    <img width="1063" alt="Screenshot 2021-07-06 at 13 37 26" src="https://user-images.githubusercontent.com/82048393/124601111-5ab4f480-de5f-11eb-8411-ac5f5c21ac1a.png">


    >As a bonus example, you can modify the `external-apis` network set to include `*.google.com` domain name which would allow access to Google subdomains. If you do it, you can would allow acess to subdomains like `www.google.com`, `docs.google.com`, etc.

# Module 7: Zone-Based Architecture

Introduce a new application into your test cluster:
```
kubectl apply -f https://installer.calicocloud.io/storefront-demo.yaml
```

Create a tier for the new zone-based policies:
```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/CCSecOps/main/Tiers/storefront.yaml
```




# Module 8: Anonymization Attacks
EJR VPN feed targets major VPN providers and their infrastructure used in anonymization activity over the internet. The feed is updated bi-monthly, which helps network security teams to stay on top of threats from such anonymizing infrastructure and detect them early in the enumeration phase.
Download:
```
wget https://docs.tigera.io/v3.7/manifests/threatdef/ejr-vpn.yaml
```
Apply:
```
kubectl apply -f ejr-vpn.yaml
```
The Tor Bulk Exit feed lists available Tor exit nodes on the internet which are used by Tor network. The list continuously updated and maintained by the Tor project. An attacker using Tor network, is likely to use one of the bulk exit nodes to connect to your infrastructure. The network security teams can detect such activity with Tor bulk exit feed and investigate as required.

Download:
```
wget https://docs.tigera.io/v3.7/manifests/threatdef/tor-exit-feed.yaml
```
Apply:
```
kubectl apply -f tor-exit-feed.yaml
```
Now, you can monitor the Dashboard for any malicious activity. The dashboard can be found at Calico Enterprise Manager, go to “kibana” and then go to “Dashboard”. Select “Tor-VPN Dashboard”.

kubectl get globalthreatfeeds 


# Module 9: Securing EKS hosts

**Goal:** Secure EKS hosts ports with network policies.

Calico network policies not only can secure pod to pod communications but also can be applied to EKS hosts to protect host based services and ports. For more details refer to [Protect Kubernetes nodes](https://docs.tigera.io/security/kubernetes-nodes) documentaiton.

## Steps

I'm building this scenario around a generic 3 node cluster - master, worker and etcd node:


![Screenshot 2021-06-17 at 14 17 46](https://user-images.githubusercontent.com/82048393/122404102-d74a6680-cf76-11eb-88a3-8ee1219280e9.png)


Automatically register your nodes as Host Endpoints (HEPS). To enable automatic host endpoints, edit the default KubeControllersConfiguration instance, and set spec.controllers.node.hostEndpoint.autoCreate to true:

```
kubectl patch kubecontrollersconfiguration default --patch='{"spec": {"controllers": {"node": {"hostEndpoint": {"autoCreate": "Enabled"}}}}}'
```

<img width="1560" alt="Screenshot 2021-06-17 at 14 14 55" src="https://user-images.githubusercontent.com/82048393/122403683-7753c000-cf76-11eb-9016-ac84ce09297c.png">

to add the label kubernetes-host to all nodes and their host endpoints:

```
kubectl label nodes --all kubernetes-host=
```

![Screenshot 2021-06-17 at 14 20 09](https://user-images.githubusercontent.com/82048393/122404637-4de76400-cf77-11eb-81d2-f63bb46b2779.png)



This tutorial assumes that you already have a tier called 'eks-nodes' in Calico Cloud:

```
cat << EOF > eks-nodes.yaml
apiVersion: projectcalico.org/v3
kind: Tier
metadata:
  name: eks-nodes
spec:
  order: 350
EOF  
```

```
kubectl apply -f eks-nodes.yaml
```

<img width="637" alt="Screenshot 2021-06-17 at 14 22 27" src="https://user-images.githubusercontent.com/82048393/122404854-7a9b7b80-cf77-11eb-96cf-55caf84d8353.png">


# etcd-nodes

Once the tier is created, build a policy for the ETCD nodes:


```
cat << EOF > etcd-nodes.yaml
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: eks-nodes.etcd-nodes
spec:
  tier: eks-nodes
  order: 0
  selector: has(kubernetes-host) && environment == 'etcd'
  namespaceSelector: ''
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      protocol: TCP
      source: {}
      destination:
        ports:
          - '2376'
          - '2379'
          - '2380'
          - '9099'
          - '10250'
    - action: Allow
      protocol: UDP
      source: {}
      destination:
        ports:
          - '8472'
  egress:
    - action: Allow
      protocol: TCP
      source: {}
      destination:
        ports:
          - '443'
          - '2379'
          - '2380'
          - '6443'
          - '9099'
    - action: Allow
      protocol: UDP
      source: {}
      destination:
        ports:
          - '8472'
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
EOF  
```

```
kubectl apply -f etcd-nodes.yaml
```

<img width="637" alt="Screenshot 2021-06-17 at 14 23 41" src="https://user-images.githubusercontent.com/82048393/122405073-a74f9300-cf77-11eb-865a-8ac3ffcb077f.png">


# Control-plane-nodes (Master Node)

Now proceed to build a policy for the master nodes:


```
cat << EOF > control-plane-nodes.yaml
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: eks-nodes.control-plane-nodes
spec:
  tier: eks-nodes
  order: 100
  selector: has(kubernetes-host) && environment == 'master'
  namespaceSelector: ''
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      protocol: TCP
      source: {}
      destination:
        ports:
          - '80'
          - '443'
          - '2376'
          - '6443'
          - '9099'
          - '10250'
    - action: Allow
      protocol: UDP
      source: {}
      destination:
        ports:
          - '8472'
  egress:
    - action: Allow
      protocol: TCP
      source: {}
      destination:
        ports:
          - '443'
          - '2379'
          - '2380'
          - '9099'
          - '10250'
          - '10254'
    - action: Allow
      protocol: UDP
      source: {}
      destination:
        ports:
          - '8472'
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
EOF  
```

```
kubectl apply -f control-plane-nodes.yaml
```

<img width="621" alt="Screenshot 2021-06-17 at 14 25 14" src="https://user-images.githubusercontent.com/82048393/122405314-da922200-cf77-11eb-8b74-a088b5ed16ad.png">


# worker-nodes

Finally, we can build a policy for the worker nodes:


```
cat << EOF > worker-nodes.yaml
apiVersion: projectcalico.org/v3
kind: StagedGlobalNetworkPolicy
metadata:
  name: eks-nodes.worker-nodes
spec:
  tier: eks-nodes
  order: 200
  selector: has(kubernetes-host) && environment == 'worker'
  namespaceSelector: ''
  serviceAccountSelector: ''
  ingress:
    - action: Allow
      protocol: TCP
      source: {}
      destination:
        ports:
          - '22'
          - '3389'
          - '80'
          - '443'
          - '2376'
          - '9099'
          - '10250'
          - '10254'
    - action: Allow
      protocol: UDP
      source: {}
      destination:
        ports:
          - '8472'
  egress:
    - action: Allow
      protocol: TCP
      source: {}
      destination:
        ports:
          - '443'
          - '6443'
          - '9099'
          - '10254'
    - action: Allow
      protocol: UDP
      source: {}
      destination:
        ports:
          - '8472'
  doNotTrack: false
  applyOnForward: false
  preDNAT: false
  types:
    - Ingress
    - Egress
EOF  
```

```
kubectl apply -f worker-nodes.yaml
```

<img width="615" alt="Screenshot 2021-06-17 at 14 26 22" src="https://user-images.githubusercontent.com/82048393/122405523-09a89380-cf78-11eb-8295-509a8ff953f2.png">

# Download node policies into your own cluster
```
wget https://raw.githubusercontent.com/n1g3ld0uglas/calico-enterprise-eks-workshop/main/hostpolicies/etcd.yaml
```
```
wget https://raw.githubusercontent.com/n1g3ld0uglas/calico-enterprise-eks-workshop/main/hostpolicies/master.yaml
```
```
wget https://raw.githubusercontent.com/n1g3ld0uglas/calico-enterprise-eks-workshop/main/hostpolicies/worker.yaml
```

# Label based on node purpose

To select a specific set of host endpoints (and their corresponding Kubernetes nodes), use a policy selector that selects a label unique to that set of host endpoints. For example, if we want to add the label environment=dev to nodes named node1 and node2:

```
kubectl label node ip-10-0-1-165 environment=master
kubectl label node ip-10-0-1-167 environment=worker
kubectl label node ip-10-0-1-227 environment=etcd
```

![Screenshot 2021-06-17 at 14 31 27](https://user-images.githubusercontent.com/82048393/122406788-06fa6e00-cf79-11eb-9bd9-4e5882e51e00.png)

Once correctly labeled, you can see the policy applying to each host endpoint:

<img width="1756" alt="Screenshot 2021-06-17 at 14 41 01" src="https://user-images.githubusercontent.com/82048393/122408405-45dcf380-cf7a-11eb-9d02-213994d950d5.png">

Alternatively, you can build a policy for worker nodes access to localhost:

```
kubectl apply -f - << EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: ingress-k8s-workers
spec:
  selector: has(kubernetes-worker)
  # Allow all traffic to localhost.
  ingress:
  - action: Allow
    destination:
      nets:
      - 127.0.0.1/32
  # Allow only the masters access to the nodes kubelet API.
  - action: Allow
    protocol: TCP
    source:
      selector: has(node-role.kubernetes.io/master)
    destination:
      ports:
      - 10250
EOF
```


    
    
# Module 10: Using observability tools

**Goal:** Explore Calico observability tools.

## Calico observability tools

>If you are interested in enabling collection of application layer metrics for your workloads, refer to [Configure L7 logs](https://docs.tigera.io/visibility/elastic/l7/configure) documentation to enable application layer metrics collection.

1. Dashboard

    The `Dashboard` view in the Enterprise Manager UI presents high level overview of what's going on in your cluster. The view shows the following information:

    - Connections, Allowed Bytes and Packets
    - Denied Bytes and Packets
    - Total number of Policies, Endpoints and Nodes
    - Summary of CIS benchmarks
    - Count of triggered alerts
    - Packets by Policy histogram that shows allowed and denied traffic as it is being evaluated by network policies

   <img width="1570" alt="1" src="https://user-images.githubusercontent.com/82048393/124572643-b459f680-de40-11eb-8950-5d8059d323e9.png">


2. Policies Board

    The `Policies Board` shows all policies deployed in the cluster and organized into `policy tiers`. You can control what a user can see and do by configuring Kubernetes RBAC roles which determine what the user can see in this view. You can also use controls to hide away tiers you're not interested in at any given time.

    <img width="1420" alt="2" src="https://user-images.githubusercontent.com/82048393/124572667-b9b74100-de40-11eb-87e8-d22864726442.png">


    By leveraging stats controls you can toggle additional metrics to be listed for each shown policy.

    <img width="1569" alt="3" src="https://user-images.githubusercontent.com/82048393/124572695-bfad2200-de40-11eb-8409-587cc2b89d1c.png">


3. Audit timeline

    The `Timeline` view shows audit trail of created, deleted, or modified resources.

    <img width="1419" alt="4" src="https://user-images.githubusercontent.com/82048393/124572715-c50a6c80-de40-11eb-8d7d-6d24b4bee192.png">


4. Endpoints

    The `Endpoints` view lists all endpoints known to Calico. It includes all Kubernetes endpoints, such as Pods, as well as Host endpoints that can represent a Kubernetes host or an external VM or bare metal machine.

   <img width="1421" alt="5" src="https://user-images.githubusercontent.com/82048393/124572735-c9cf2080-de40-11eb-9b8f-deba4a337e1a.png">


5. Service Graph

    The dynamic `Service Graph` presents network flows from service level perspective. Top level view shows how traffic flows between namespaces as well as external and internal endpoints.

    <img width="1415" alt="6" src="https://user-images.githubusercontent.com/82048393/124572860-e66b5880-de40-11eb-9665-8760968fbbdc.png">


    - When you select any node representing a namespace, you will get additional details about the namespace, such as incoming and outgoing traffic, policies evaluating each flow, and DNS metrics.
    - When you select any edge, you will get details about the flows representing that edge.
    - If you expand a namespace by double-clicking on it, you will get the view of all components of the namespace.

6. Flow Visualizations

    The `Flow Visualizations` view shows all point-to-point flows in the cluster. It allows you to see the cluster traffic from the network point of view.

    <img width="1569" alt="7" src="https://user-images.githubusercontent.com/82048393/124572877-ebc8a300-de40-11eb-80d6-2ae40ead9c1a.png">


7. Kibana dashboards

    The `Kibana` components comes with Calico commercial offerings and provides you access to raw flow, audit, and dns logs, as well as ability to visualize the collected data in various dashboards.

    <img width="1625" alt="8" src="https://user-images.githubusercontent.com/82048393/124572903-eff4c080-de40-11eb-911d-9e244acbc400.png">


    Some of the default dashboards you get access to are DNS Logs, Flow Logs, Audit Logs, Kuernetes API calls, L7 HTTP metrics, and others.    
    
    



# Module 11: Using compliance reports

**Goal:** Use global reports to satisfy compliance requirements.

## Steps

1. Use `Compliance Reports` view to see all generated reports.

    >We have deployed a few compliance reports in one of the first labs and by this time a few reports should have been already generated. If you don't see any reports, you can manually kick off report generation task. Follow the steps below if you need to do so.

    Calico provides `GlobalReport` resource to offer [Compliance reports](https://docs.tigera.io/compliance/compliance-reports/) capability. There are several types of reports that you can configure:

    - CIS benchmarks
    - Inventory
    - Network access
    - Policy audit

    >When using EKS cluster, you need to [enable and configure audit log collection](https://docs.tigera.io/compliance/compliance-reports/compliance-managed-cloud#enable-audit-logs-in-eks) on AWS side in order to get the data captured for the `policy-audit` reports.

    A compliance report could be configured to include only specific endpoints leveraging endpoint labels and selectors. Each report has the `schedule` field that determines how often the report is going to be generated and sets the timeframe for the data to be included into the report.

    Compliance reports organize data in a CSV format which can be downloaded and moved to a long term data storage to meet compliance requirements.

    <img width="1571" alt="compliance-report" src="https://user-images.githubusercontent.com/82048393/124574593-85dd1b00-de42-11eb-8f30-88892486e8b5.png">


2. *[Optional]* Manually kick off report generation task.

    >In order to generate a compliance report, Calico needs at least 1 hour worth of data for `inventory`, `network-access` reports, and at least 24 hours worth of data for `cis` reports. If commands below don't result in any reports being generated, give it some time and then retry the report generation.

    It is possible to kick off report generation via a one off job.

    ```bash
    # get Calico version
    CALICO_VERSION=$(kubectl get clusterinformation default -ojsonpath='{.spec.cnxVersion}')
    # set report names
    CIS_REPORT_NAME='daily-cis-results'
    INVENTORY_REPORT_NAME='cluster-inventory'
    NETWORK_ACCESS_REPORT_NAME='cluster-network-access'
    
    # enable if you configured audit logs for EKS cluster and uncommented policy audit reporter job
    # you also need to add variable replacement in the sed command below
    # POLICY_AUDIT_REPORT_NAME='cluster-policy-audit'

    # get compliance reporter token
    COMPLIANCE_REPORTER_TOKEN=$(kubectl get secrets -n tigera-compliance | grep 'tigera-compliance-reporter-token*' | awk '{print $1;}')

    # replace variables in YAML and deploy reporter jobs
    sed -e "s?<COMPLIANCE_REPORTER_TOKEN>?$COMPLIANCE_REPORTER_TOKEN?g" \
      -e "s?<CALICO_VERSION>?$CALICO_VERSION?g" \
      -e "s?<CIS_REPORT_NAME>?$CIS_REPORT_NAME?g" \
      -e "s?<INVENTORY_REPORT_NAME>?$INVENTORY_REPORT_NAME?g" \
      -e "s?<NETWORK_ACCESS_REPORT_NAME>?$NETWORK_ACCESS_REPORT_NAME?g" \
      -e "s?<REPORT_START_TIME_UTC>?$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ')?g" \
      -e "s?<REPORT_END_TIME_UTC>?$(date -u +'%Y-%m-%dT%H:%M:%SZ')?g" \
      demo/40-compliance-reports/cluster-reporter-jobs.yaml | kubectl apply -f -
    ```
    
 
 
 # Module 12: Using alerts

**Goal:** Use global alerts to notify security and operations teams about unsanctioned or suspicious activity.

## Steps

1. Review alerts manifests.

    Navigate to `demo/50-alerts` and review YAML manifests that represent alerts definitions. Each file containes an alert template and alert definition. Alerts templates can be used to quickly create an alert definition in the UI.

2. View triggered alerts.

    >We implemented alerts in one of the first labs in order to see how our activity can trigger them.

    Open `Alerts` view to see all triggered alerts in the cluster. Review the generated alerts.

    <img width="1573" alt="alerts-view" src="https://user-images.githubusercontent.com/82048393/124574835-c341a880-de42-11eb-8c5b-27a4502f1dce.png">


    You can also review the alerts configuration and templates by navigating to alerts configuration in the top right corner.
 
 





# Module 13: Dynamic packet capture

**Goal:** Configure packet capture for specific pods and review captured payload.

## Steps

Check that there are no packet captures in this directory  
```
ls *pcap
```
A Packet Capture resource (PacketCapture) represents captured live traffic for debugging microservices and application interaction inside a Kubernetes cluster.</br>
https://docs.tigera.io/reference/calicoctl/captured-packets  
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/workloads/packet-capture.yaml
```
Confirm this is now running:  
```  
kubectl get packetcapture -n storefront
```
Once the capture is created, you can delete the collector:
```
kubectl delete -f https://raw.githubusercontent.com/tigera-solutions/aws-howdy-parter-calico-cloud/main/workloads/packet-capture.yaml
```
#### Install a Calicoctl plugin  
Use the following command to download the calicoctl binary:</br>
https://docs.tigera.io/maintenance/clis/calicoctl/install#install-calicoctl-as-a-kubectl-plugin-on-a-single-host
``` 
curl -o kubectl-calico -O -L  https://docs.tigera.io/download/binaries/v3.7.0/calicoctl
``` 
Set the file to be executable.
``` 
chmod +x kubectl-calico
```
Verify the plugin works:
``` 
./kubectl-calico -h
``` 
#### Move the packet capture
```
./kubectl-calico captured-packets copy storefront-capture -n storefront
``` 
Check that the packet captures are now created:
```
ls *pcap
```
#### Install TSHARK and troubleshoot per pod 
Use Yum To Search For The Package That Installs Tshark:</br>
https://www.question-defense.com/2010/03/07/install-tshark-on-centos-linux-using-the-yum-package-manager
```  
sudo yum install wireshark
```  
```  
tshark -r frontend-75875cb97c-2fkt2_enib222096b242.pcap -2 -R dns | grep microservice1
``` 
```  
tshark -r frontend-75875cb97c-2fkt2_enib222096b242.pcap -2 -R dns | grep microservice2
```  

Congratulations! You have finished all the labs in the workshop.


# HoneyPods

Apply the following manifest to create a namespace and RBAC for the honeypods:
```
kubectl apply -f https://docs.tigera.io/v3.7/manifests/threatdef/honeypod/common.yaml 
```

```
kubectl get secret tigera-pull-secret -n tigera-guardian -o json > pull-secret.json
```

edit pull-secret.json, remove creation timestamp, and change namespace from tigera-guardian to tigera-internal

```
kubectl apply -f pull-secret.json -n tigera-internal
```

IP Enumeration: Expose a empty pod that can only be reached via PodIP, we can see when the attacker is probing the pod network:
```
kubectl apply -f https://docs.tigera.io/v3.7/manifests/threatdef/honeypod/ip-enum.yaml 
```
Exposed Nginx Service: Expose a nginx service that serves a generic page. The pod can be discovered via ClusterIP or DNS lookup. 
An unreachable service tigera-dashboard-internal-service is created to entice the attacker to find and reach, tigera-dashboard-internal-debug:
```
kubectl apply -f https://docs.tigera.io/v3.7/manifests/threatdef/honeypod/expose-svc.yaml 
```

```
kubectl apply -f https://docs.tigera.io/v3.7/manifests/threatdef/honeypod/vuln-svc.yaml 
```

<img width="914" alt="Screenshot 2021-06-29 at 12 14 03" src="https://user-images.githubusercontent.com/82048393/123788193-a3a30100-d8d3-11eb-9299-7891c1fa23e9.png">


Verify honeypods deployment

```
kubectl get pods -n tigera-internal
```

```
kubectl get globalalerts
```

<img width="561" alt="Screenshot 2021-06-29 at 12 15 38" src="https://user-images.githubusercontent.com/82048393/123788296-be757580-d8d3-11eb-9841-45b0d3f7ab3d.png">


Once you have verified that the honeypods are installed and working, it is recommended to remove the pull secret from the namespace:

```
kubectl delete secret tigera-pull-secret -n tigera-internal
```





# Scaling down your test cluster

```
eksctl get cluster
```

```
eksctl get nodegroup --cluster nigel-eks-cluster2
```

```
eksctl scale nodegroup --cluster nigel-eks-cluster2 --name ng-f22ea39f --nodes 0
```

<img width="937" alt="Screenshot 2021-07-06 at 16 54 57" src="https://user-images.githubusercontent.com/82048393/124631212-10da0780-de7b-11eb-96c0-f4041e97788d.png">





    
    
  ![Calico-Networking-For-Kubernetes](https://user-images.githubusercontent.com/82048393/124490722-60043780-ddaa-11eb-80a9-4dab4cf3313c.png)
  

# Adding the Google Boutique Application

Apply the manifests for the applications
```
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
```

Apply the policies for the application
```
kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/boutiqueshop/policies.yaml
```

Delete the manifests for the applications
```
kubectl delete -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
```

Delete the policies for the application
```
kubectl delete -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/boutiqueshop/policies.yaml
```

# RBAC login for Calico Enterprise

Login with full network admin priveleges:
```
kubectl get secret $(kubectl get serviceaccount nigel -o jsonpath='{range .secrets[*]}{.name}{"\n"}{end}' | grep token) -o go-template='{{.data.token | base64decode}}' && echo
```

Login with limitied read-only user priveleges:
```
kubectl get secret $(kubectl get serviceaccount taher -o jsonpath='{range .secrets[*]}{.name}{"\n"}{end}' | grep token) -o go-template='{{.data.token | base64decode}}' && echo
```


# Connect Cluster with a unique naming convention

When you join a cluster to a shared CC instance, try to prefix it with your name so that it’s easy to tell what’s yours if you forget to add the ```owner``` label:

```
CLUSTER_PREFIX='nigel-eks'
curl -s https://installer.calicocloud.io/XXXXXXXXXXXX-management_install.sh | sed -e "s/CLUSTER_NAME=.*$/CLUSTER_NAME=${CLUSTER_PREFIX}/1" | bash
```  
