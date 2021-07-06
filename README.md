# calico-enterprise-eks-workshop
Kubernetes Security and Observability for EKS Workshop

# Module 2: Creating EKS cluster

**Goal:** Create EKS cluster.

This workshop uses EKS cluster with most of the default configuration settings. 
>To create an EKS cluster and tune the default settings, consider exploring [EKS Workshop](https://www.eksworkshop.com) materials.

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



# Module 3: Joining EKS cluster to Calico Cloud

**Goal:** Join EKS cluster to Calico Cloud management plane.

>In order to complete this module, you must have [Calico Cloud trial account](https://www.tigera.io/tigera-products/calico-cloud/).

## Steps

1. Join EKS cluster to Calico Cloud management plane.

    Use Calico Cloud install script provided in the welcome email for Calico Cloud trial account.

    ```
    # script should look similar to this
    curl https://installer.calicocloud.io/xxxxxx_yyyyyyy-saay-management_install.sh | bash
    ```

    Joining the cluster to Calico Cloud can take a few minutes. Wait for the installation script to finish before you proceed to the next step.

    You should see the output similar to this:

    ```text
    [INFO] Checking for installed CNI Plugin
    [INFO] Deploying CRDs and Tigera Operator
    [INFO] Creating Tigera Pull Secret
    [INFO] Tigera Operator is Available
    [INFO] Adding Installation CR for Enterprise install
    [WAIT] Tigera calico is Progressing
    [INFO] Tigera Calico is Available
    [INFO] Deploying Tigera Prometheus Operator
    podmonitors.monitoring.coreos.com
    [INFO] Deploying CRs for Managed Cluster
    [INFO] Tigera Apiserver is Available
    [INFO] Generate New Cluster Registration Manifest
    [INFO] Creating connection
    [INFO] All Tigera Components are Available
    [INFO] Securing Install
    .....
    ```

2. Configure log aggregation and flush intervals.

    ```
    kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFlushInterval":"10s"}}'
    kubectl patch felixconfiguration.p default -p '{"spec":{"dnsLogsFlushInterval":"10s"}}'
    kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
    ```

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

This will add tiers `security` and `platform` to the Calico cluster.

2. Deploy base policy.

    In order to explicitly allow workloads to connect to the Kubernetes DNS component, we are going to implement a policy that controls such traffic.

```
cat << EOF > allow-kube-dns.yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: platform.allow-kube-dns
spec:
  # requires platform tier to exist
  tier: platform
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

3. Deploy demo applications.

    ```
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/dev/app.manifests.yaml
    ```
    ```
    kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
    ```

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
  name: cluster-inventory
spec:
  reportType: inventory
  schedule: '*/30 * * * *'

---
apiVersion: projectcalico.org/v3
kind: GlobalReport
metadata:
  name: cluster-network-access
spec:
  reportType: network-access
  schedule: '*/30 * * * *'

# uncomment policy-audit report if you configured audit logs for EKS cluster https://docs.tigera.io/compliance/compliance-reports/compliance-managed-cloud#enable-audit-logs-in-eks
# ---
# apiVersion: projectcalico.org/v3
# kind: GlobalReport
# metadata:
#   name: cluster-policy-audit
# spec:
#   reportType: policy-audit
#   schedule: '*/30 * * * *'
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

    b. Test connectivity across namespaces.

    Test connectivity from dev namespace to default namespace
    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://frontend.default 2>/dev/null | grep -i http'
    ```
    Test connectivity from default namespace to dev namespace
    ```
    kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI http://nginx-svc.dev 2>/dev/null | grep -i http'
    ```

    c. Test connectivity from each namespace to the Internet.

    
    Test connectivity from dev namespace to the Internet
    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://www.google.com 2>/dev/null | grep -i http'
    ```
    
   Test connectivity from default namespace to the Internet
   ```
   kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI www.google.com 2>/dev/null | grep -i http'
   ```

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

    ```
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/10-security-controls/staged.default-deny.yaml
    ```

    You should be able to view the potential affect of the staged `default-deny` policy if you navigate to the `Dashboard` view in the Enterprise Manager UI and look at the `Packets by Policy` histogram.

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

    Now as we have proper policies in place, we can enforce `default-deny` policy moving closer to zero-trust security approach. You can either enforced the already deployed staged `default-deny` policy using the `Policies Board` view in the Enterirpse Manager UI, or you can apply an enforcing `default-deny` policy manifest.

    
    Apply enforcing default-deny policy manifest
    ```
    kubectl apply -f demo/10-security-controls/default-deny.yaml
    ```
    You can delete staged default-deny policy
    ```
    kubectl delete -f demo/10-security-controls/staged.default-deny.yaml
    ```

4. Test connectivity with policies in place.

    a. The only connections between the components within each namespaces should be allowed as configured by the policies.

    ```
    # test connectivity within dev namespace
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://nginx-svc 2>/dev/null | grep -i http'

    # test connectivity within default namespace
    kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI frontend 2>/dev/null | grep -i http'
    ```

    b. The connections across `dev` and `default` namespaces should be blocked by the global `default-deny` policy.

    ```bash
    # test connectivity from dev namespace to default namespace
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://frontend.default 2>/dev/null | grep -i http'

    # test connectivity from default namespace to dev namespace
    kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI http://nginx-svc.dev 2>/dev/null | grep -i http'
    ```

    c. The connections to the Internet should be blocked by the configured policies.

    ```
    # test connectivity from dev namespace to the Internet
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://www.google.com 2>/dev/null | grep -i http'

    # test connectivity from default namespace to the Internet
    kubectl exec -it $(kubectl get po -l app=loadgenerator -ojsonpath='{.items[0].metadata.name}') -- sh -c 'curl -m3 -sI www.google.com 2>/dev/null | grep -i http'
    ```

5. Protect workloads from known bad actors.

    Calico offers `GlobalThreatfeed` resource to prevent known bad actors from accessing Kubernetes pods.

    ```
    # deploy feodo tracker threatfeed
    kubectl apply -f demo/10-security-controls/feodotracker.threatfeed.yaml
    # deploy network policy that uses the threadfeed
    kubectl apply -f demo/10-security-controls/feodo-block-policy.yaml

    # try to ping any of the IPs in from the feodo tracker list
    IP=$(kubectl get globalnetworkset threatfeed.feodo-tracker -ojson | jq .spec.nets[0] | sed -e 's/^"//' -e 's/"$//' -e 's/\/32//')
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
    kubectl apply -f demo/20-egress-access-controls/centos-to-frontend.yaml
    ```

    b. Test connectivity between `dev/centos` pod and `default/frontend` service.

    ```
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -sI http://frontend.default 2>/dev/null | grep -i http'
    ```

    The access should be allowed once the egress policy is in place.

3. Implement DNS policy to allow the external endpoint access from a specific workload, e.g. `dev/centos`.

    a. Apply a policy to allow access to `api.twilio.com` endpoint using DNS rule.

    ```
    # deploy dns policy
    kubectl apply -f demo/20-egress-access-controls/dns-policy.yaml

    # test egress access to api.twilio.com
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -skI https://api.twilio.com 2>/dev/null | grep -i http'
    # test egress access to www.google.com
    kubectl -n dev exec -t centos -- sh -c 'curl -m3 -skI https://www.google.com 2>/dev/null | grep -i http'
    ```

    Access to the `api.twilio.com` endpoint should be allowed by the DNS policy but not to any other external endpoints like `www.google.com` unless we modify the policy to include that domain name.

    b. Edit the policy to use a `NetworkSet` instead of inline DNS rule.


    Deploy network set
    ```    
    kubectl apply -f demo/20-egress-access-controls/netset.external-apis.yaml
    ``` 
    Deploy DNS policy using the network set
    ``` 
    kubectl apply -f demo/20-egress-access-controls/dns-policy.netset.yaml
    ```

    >As a bonus example, you can modify the `external-apis` network set to include `*.google.com` domain name which would allow access to Google subdomains. If you do it, you can would allow acess to subdomains like `www.google.com`, `docs.google.com`, etc.


# Module 7: Securing EKS hosts

**Goal:** Secure EKS hosts ports with network policies.

Calico network policies not only can secure pod to pod communications but also can be applied to EKS hosts to protect host based services and ports. For more details refer to [Protect Kubernetes nodes](https://docs.tigera.io/security/kubernetes-nodes) documentaiton.

## Steps

1. Open a port of NodePort service for public access on EKS node.

    For the demo purpose we are going to expose the `default/frontend` service via the `NodePort` service type to open it for the public access.

    ```bash
    # expose the frontend service via the NodePort service type
    kubectl expose deployment frontend --type=NodePort --name=frontend-nodeport --overrides='{"apiVersion":"v1","spec":{"ports":[{"nodePort":30080,"port":80,"targetPort":8080}]}}'

    # open access to the port in AWS security group
    CLUSTER_NAME='tigera-workshop' # adjust the name if you used a different name for your EKS cluster
    AWS_REGION=$(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.region')
    # pick one EKS node and use it's ID to get securigy group
    SG_ID=$(aws ec2 describe-instances --region $AWS_REGION --filters "Name=tag:Name,Values=$CLUSTER_NAME*" "Name=instance-state-name,Values=running" --query 'Reservations[0].Instances[*].NetworkInterfaces[0].Groups[0].GroupId' --output text --output text)
    ```
    Open SSH port in the security group for public access
    ```
    aws ec2 authorize-security-group-ingress --region $AWS_REGION --group-id $SG_ID --protocol tcp --port 30080 --cidr 0.0.0.0/0
    ```
    
    Get public IP of an EKS node
    ```
    PUB_IP=$(aws ec2 describe-instances --region $AWS_REGION --filters "Name=tag:Name,Values=$CLUSTER_NAME*" "Name=instance-state-name,Values=running" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text --output text)
    ```
    Test connection to SSH port
    ```
    nc -zv $PUB_IP 30080
    ```

    >It can take a moment for the node port to become accessible.

    If the SSH port was configured correctly, the `nc` command should show you that the port is open.

2. Enable `HostEndpoint` auto-creation for EKS cluster.

    When working with managed Kubernetes services, such as EKS, we recommend using `HostEndpoint` (HEP) auto-creation feature which allows you to automate the management of `HostEndpoint` resources for managed Kubernetes clusters whenever the cluster is scaled.

    >Before you enable HEP auto-creation feature, make sure there are no `HostEndpoint` resources manually defined for your cluster: `kubectl get hostendpoints`.

    
    Check whether auto-creation for HEPs is enabled. Default: Disabled
    ```
    kubectl get kubecontrollersconfiguration.p default -ojsonpath='{.status.runningConfig.controllers.node.hostEndpoint.autoCreate}'
    ```
    Enable HEP auto-creation
    ```
    kubectl patch kubecontrollersconfiguration.p default -p '{"spec": {"controllers": {"node": {"hostEndpoint": {"autoCreate": "Enabled"}}}}}'
    ```
    Verify that each node got a HostEndpoint resource created
    ```
    kubectl get hostendpoints
    ```

3. Implement a Calico policy to control access to the service of NodePort type.

    Deploy a policy that only allows access to the node port from the Cloud9 instance.

    
    From your local shell test connection to the node port, i.e. 30080, using netcat or telnet or other connectivity testing tool
    EKS_NODE_PUB_IP=XX.XX.XX.XX
    ```
    nc -zv $EKS_NODE_PUB_IP 30080
    ```
    Get public IP of Cloud9 instance in the Cloud9 shell
    ```
    CLOUD9_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
    ```
    Deploy HEP policy
    ```
    sed -e "s/\${CLOUD9_IP}/${CLOUD9_IP}\/32/g" demo/30-secure-hep/frontend-nodeport-access.yaml | kubectl apply -f -
    ```
    Test access from Cloud9 shell
    ```
    nc -zv $EKS_NODE_PUB_IP 30080
    ```

    Once the policy is implemented, you should not be able to access the node port `30080` from your local shell, but you should be able to access it from the Cloud9 shell.

    >Note that in order to control access to the NodePort service, you need to enable `preDNAT` and `applyOnForward` policy settings.

4. *[Bonus task]* Implement a Calico policy to control access to the SSH port on EKS hosts.

    When dealing with SSH and platform required ports, Calico provides a fail safe mechanism to manage such posrts so that you don't lock yourself out of the node by accident. Once you configure and test host targeting policy, you can selectively disable fail safe ports.

    Deploy FelixConfiguration to disable fail safe for SSH port
    ```
    kubectl apply -f demo/30-secure-hep/felixconfiguration.yaml
    ```
    
    Get Public IP of Cloud9 instance
    ```
    CLOUD9_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
    ```
    Allow SSH access to EKS nodes only from the Cloud9 instance
    ```
    sed -e "s/\${CLOUD9_IP}/${CLOUD9_IP}\/32/g" demo/30-secure-hep/ssh-access.yaml | kubectl apply -f -
    ```
    
    
# Module 8: Using observability tools

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
    
    



# Module 9: Using compliance reports

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
    
 
 
 # Module 10: Using alerts

**Goal:** Use global alerts to notify security and operations teams about unsanctioned or suspicious activity.

## Steps

1. Review alerts manifests.

    Navigate to `demo/50-alerts` and review YAML manifests that represent alerts definitions. Each file containes an alert template and alert definition. Alerts templates can be used to quickly create an alert definition in the UI.

2. View triggered alerts.

    >We implemented alerts in one of the first labs in order to see how our activity can trigger them.

    Open `Alerts` view to see all triggered alerts in the cluster. Review the generated alerts.

    <img width="1573" alt="alerts-view" src="https://user-images.githubusercontent.com/82048393/124574835-c341a880-de42-11eb-8c5b-27a4502f1dce.png">


    You can also review the alerts configuration and templates by navigating to alerts configuration in the top right corner.
 
 





# Module 11: Dynamic packet capture

**Goal:** Configure packet capture for specific pods and review captured payload.

## Steps

1. Configure packet capture.

    Navigate to `demo/60-packet-capture` and review YAML manifests that represent packet capture definition. Each packet capture is configured by deploing a `PacketCapture` resource that targets endpoints using `selector` and `labels`.

    Deploy packet capture definition to capture packets for `dev/nginx` pods.

    ```bash
    kubectl apply -f demo/60-packet-capture/nginx-pcap.yaml
    ```

    >Once the `PacketCapture` resource is deployed, Calico starts capturing packets for all endpoints configured in the `selector` field.

2. Install `calicoctl` CLI

    The easiest way to retrieve captured `*.pcap` files is to use [calicoctl](https://docs.tigera.io/maintenance/clis/calicoctl/) CLI.

    ```bash
    # download and configure calicoctl
    curl -o calicoctl -O -L https://docs.tigera.io/download/binaries/v3.7.0/calicoctl
    chmod +x calicoctl
    sudo mv calicoctl /usr/local/bin/
    calicoctl version
    ```

3. Fetch and review captured payload.

    >The captured `*.pcap` files are stored on the hosts where pods are running at the time the `PacketCapture` resource is active.

    Retrieve captured `*.pcap` files and review the content.

    ```bash
    # get pcap files
    calicoctl captured-packets copy dev-capture-nginx --namespace dev

    ls dev-nginx*
    # view *.pcap content
    tcpdump -Xr dev-nginx-XXXXXX.pcap
    ```

4. Stop packet capture

    Stop packet capture by removing the `PacketCapture` resource.

    ```bash
    kubectl delete -f demo/60-packet-capture/nginx-pcap.yaml
    ```

Congratulations! You have finished all the labs in the workshop.




    
    
  ![Calico-Networking-For-Kubernetes](https://user-images.githubusercontent.com/82048393/124490722-60043780-ddaa-11eb-80a9-4dab4cf3313c.png)
    
Slides accessible here:
https://docs.google.com/presentation/d/1agl2xbuBNYRUASEBynV-8cpcL58UeHZcpE627dVnwJU/edit#slide=id.g79881f7cab_2_73
