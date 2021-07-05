# calico-enterprise-eks-workshop
Kubernetes Security and Observability for EKS Workshop

# Module 3: Joining EKS cluster to Calico Cloud

**Goal:** Join EKS cluster to Calico Cloud management plane.

>In order to complete this module, you must have [Calico Cloud trial account](https://www.tigera.io/tigera-products/calico-cloud/).

## Steps

1. Join EKS cluster to Calico Cloud management plane.

    Use Calico Cloud install script provided in the welcome email for Calico Cloud trial account.

    ```bash
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

    ```bash
    kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFlushInterval":"10s"}}'
    kubectl patch felixconfiguration.p default -p '{"spec":{"dnsLogsFlushInterval":"10s"}}'
    kubectl patch felixconfiguration.p default -p '{"spec":{"flowLogsFileAggregationKindForAllowed":1}}'
    ```

3. Configure Felix for log data collection.

    >[Felix](https://docs.tigera.io/reference/architecture/overview#felix) is one of Calico components that is responsible for configuring routes, ACLs, and anything else required on the host to provide desired connectivity for the endpoints on that host.

    ```bash
    kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"policySyncPathPrefix":"/var/run/nodeagent","l7LogsFileEnabled":true}}'
    ```
    
    
 
# Module 4: Configuring demo applications

**Goal:** Deploy and configure demo applications.

## Steps

1. Deploy policy tiers.

    We are going to deploy some policies into policy tier to take advantage of hierarcical policy management.
    
```bash
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

    ```bash
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
    # deploy dev app stack
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/dev/app.manifests.yaml

    # deploy boutiqueshop app stack
    kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/master/release/kubernetes-manifests.yaml
    ```

4. Deploy compliance reports.

    >The reports will be needed for one of a later lab.

    ```
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/40-compliance-reports/daily-cis-results.yaml
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/40-compliance-reports/cluster-reports.yaml
    ```

5. Deploy global alerts.

    >The alerts will be explored in a later lab.

    ```
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/globalnetworkset.changed.yaml
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/unsanctioned.dns.access.yaml
    kubectl apply -f https://raw.githubusercontent.com/tigera-solutions/tigera-eks-workshop/main/demo/50-alerts/unsanctioned.lateral.access.yaml
    ```
