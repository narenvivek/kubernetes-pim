# Addressing Authorization and Privilege Escalation issues in a Kubernetes Cluster

Managing privileges in a Kubernetes cluster is hard! Why? If you spin-up a plain vanilla cluster, you get:

<b> 38 Subjects (Service Principals) associated to one or more of 51 roles through one or more of 43 role bindings </b>

This was true for a 2020 version of K8s implementation (1.18 or 1.19). Although, in-cluster identity management is done well, introducing more resources (through Custom Resource Definitions [CRDs](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/)) will invariably introduce more machine identities (or service principals) to facilitate applications' interaction within the cluster. 

The security concern is - just one misconfigured machine identity (service account) could compromise the cluster. Although this issue might not be significant in case of a standalone cluster, organizations who indend to use enterprise-wide shared clusters (enterprise-wide shared clusters are becoming a norm) should be cautious of service principals/accounts with higher privs.

This short article attempts to go through two useful tools that provides visibility to privilige identify misconfigurations within K8s cluster. 

## How can an attacker take control of the cluster?

In any cluster, if you want to see service principals in your cluster, run the following command:

<pre>
$ <b>kubectl get sp --all-namespaces</b>
</pre>

Pick any of the service principals from the namespace `kube-system`. Each one of them, when misused, can damage the cluster or allow hackers to exfilterate data and/or secrets from the cluster. Assuming user authentication to API server within the cluster is weak, a hacker simply needs to insert a pod into the cluster associating the pod with one of the `kube-system` service principals. That's it!

Below is an example of how:

<pre>
apiVersion: v1
kind: Pod
metadata:
  name: static-web
  labels:
    role: myrole
spec:
  containers:
    - name: web
      image: nginx
      ports:
        - name: web
          containerPort: 80
          protocol: TCP
  <b>serviceAccountName: certificate-controller</b>
  <b>autoMountServiceAccountToken: true</b>
</pre>

# Find those misconfigurations
Simplest way to identify issues with higher privilege of service accounts is to two use two new(ish) tools:

## 1. Kubescape
If you are looking to align with the latest hardending guidelines released by US CISA and NSA, this might be the best tool that could use at the moment. Installation instruction and configuration is [here](https://github.com/armosec/kubescape).

In my simple setup I have three applications running in my cluster - WebGoat, Nginx (web) and Flux (GitOps agents). Although, none of them have higher privs but illustrates how to use the tools.

Once `kubescape` is installed, it should be a fairly simple scan if your `.kube/config` is correctly setup.

```
$ kubectl get ns

NAME                   STATUS   AGE
default                Active   33d
flux-system            Active   5d10h
kube-node-lease        Active   33d
kube-public            Active   33d
kube-system            Active   33d
kubernetes-dashboard   Active   5d10h
```

Webgoat and Nginx reside in my default namespace (tried to emulate a shared cluster) and Flux is in flux-system namespace.

```
$ kubectl get po -n default

NAME                      READY   STATUS    RESTARTS   AGE
mygoat                    1/1     Running   0          24m
nginx-6799fc88d8-xl5fr    1/1     Running   0          26m
podinfo-96c5c65f6-8m59h   1/1     Running   0          5d10h
podinfo-96c5c65f6-j5pm5   1/1     Running   0          5d10h

$ kubectl get po -n flux-system

NAME                                       READY   STATUS    RESTARTS   AGE
helm-controller-7b58d45956-tdnk9           1/1     Running   0          5d11h
kustomize-controller-bb6c99658-r722m       1/1     Running   0          5d11h
notification-controller-5f4f4967b9-h89rh   1/1     Running   0          5d11h
source-controller-6448c7989-wsbvh          1/1     Running   0          5d11h

```
Now, let us run `kubescape`:

```
$ kubescape scan framework nsa --exclude-namespaces kube-system,kube-public
```

To view service account security issues, (cluster) roles and (cluster) rolebinding, focus on sections in the report that looks similar to:


<pre>
<b>[control: Automatic mapping of service account] failed 😥 </b>

Description: Potential attacker may gain access to a POD and steal its service account token. Therefore, it is recommended to disable automatic mapping of the service account tokens in service account configuration and enable it only for PODs that need to use them.
   Namespace kubernetes-dashboard
      ServiceAccount - default
      ServiceAccount - kubernetes-dashboard
   Namespace default
      ServiceAccount - default
   Namespace flux-system
      ServiceAccount - default
      ServiceAccount - helm-controller
      ServiceAccount - kustomize-controller
      ServiceAccount - notification-controller
      ServiceAccount - source-controller
   Namespace kube-node-lease
      ServiceAccount - default
Summary - Passed:0   Failed:9   Total:9

<b>[control: Cluster-admin binding] failed 😥 </b>
Description: Attackers who have Cluster-admin permissions, or permissions to create bindings and cluster-bindings can take advantage of their high privileges for malicious intentions. Determines which subjects have cluster admin permissions.
      ClusterRole - cluster-admin
      ClusterRoleBinding - cluster-admin
      ClusterRoleBinding - cluster-reconciler-flux-system
      ClusterRoleBinding - kubernetes-dashboard
      ClusterRoleBinding - minikube-rbac
      ClusterRole - crd-controller-flux-system
      ClusterRoleBinding - crd-controller-flux-system
      ClusterRole - system:controller:daemon-set-controller
      ClusterRoleBinding - system:controller:daemon-set-controller
      ClusterRole - system:controller:job-controller
      ClusterRoleBinding - system:controller:job-controller
      ClusterRole - system:controller:persistent-volume-binder
      ClusterRoleBinding - system:controller:persistent-volume-binder
      ClusterRole - system:controller:replicaset-controller
      ClusterRoleBinding - system:controller:replicaset-controller
      ClusterRole - system:controller:replication-controller
      ClusterRoleBinding - system:controller:replication-controller
      ClusterRole - system:controller:statefulset-controller
      ClusterRoleBinding - system:controller:statefulset-controller
Summary - Passed:103   Failed:19   Total:122
</pre>

Although this section gives you useful details, it lacks the details on 'how' the service accounts are assigned privileges. This is where CyberArk open-source (I have checked - it is GPL 3.0 OSS license) tool `Kubiscan` comes handy.

## 2. Kubiscan

Believe it or not, this is an Open Source tool that CyberArk provides (I have checked - it is GPL/3 OSS)! In my opinion, this is a well-written Python based tool that clearly identifies risky Service Accounts. While we got a "list" of service accounts, role(s) and role-bindings using `Kubescape`, it does not delve into the next level of detail to provide us with a view of authorization levels (or 'verbs') aligned to the roles and hence to service accounts. `Kubiscan` does a great job at this:

(you might need to do a little bit of configuration to ensure that the tool works correctly but I assume that the tool is setup correctly)

<pre>

To find risky users and service accounts in my cluster:

$ <b> kubiscan -rs </b>

+-----------+
|Risky Users|
+----------+----------------+----------------------+--------------------------------+
| Priority | Kind           | Namespace            | Name                           |
+----------+----------------+----------------------+--------------------------------+
| CRITICAL | Group          | None                 | system:masters                 |
| <b> CRITICAL | ServiceAccount | flux-system          | kustomize-controller </b>           |
| CRITICAL | ServiceAccount | flux-system          | helm-controller                |
| CRITICAL | ServiceAccount | flux-system          | source-controller              |
| CRITICAL | ServiceAccount | flux-system          | notification-controller        |
| CRITICAL | ServiceAccount | flux-system          | image-reflector-controller     |
| CRITICAL | ServiceAccount | flux-system          | image-automation-controller    |
| CRITICAL | ServiceAccount | kubernetes-dashboard | kubernetes-dashboard           |
| CRITICAL | ServiceAccount | kube-system          | default                        |
| HIGH     | ServiceAccount | kube-system          | cronjob-controller             |
| HIGH     | ServiceAccount | kube-system          | daemon-set-controller          |
| HIGH     | ServiceAccount | kube-system          | deployment-controller          |
| CRITICAL | ServiceAccount | kube-system          | expand-controller              |
| CRITICAL | ServiceAccount | kube-system          | generic-garbage-collector      |
| CRITICAL | ServiceAccount | kube-system          | horizontal-pod-autoscaler      |
| HIGH     | ServiceAccount | kube-system          | job-controller                 |
| CRITICAL | ServiceAccount | kube-system          | namespace-controller           |
| CRITICAL | ServiceAccount | kube-system          | persistent-volume-binder       |
| HIGH     | ServiceAccount | kube-system          | replicaset-controller          |
| HIGH     | ServiceAccount | kube-system          | replication-controller         |
| CRITICAL | ServiceAccount | kube-system          | resourcequota-controller       |
| HIGH     | ServiceAccount | kube-system          | statefulset-controller         |
| CRITICAL | User           | None                 | system:kube-controller-manager |
| CRITICAL | ServiceAccount | kube-system          | bootstrap-signer               |
| CRITICAL | ServiceAccount | kube-system          | token-cleaner                  |
+----------+----------------+----------------------+--------------------------------+
</pre>

This gives us a more useful list with its own assessment of criticality (depending on the authorization levels). Modifying some of the service accounts' privilege levels WILL break your cluster. However, if you see service accounts in a namespace that hosts an application (incl. default) and `Kubiscan` tells you that it is CRITICAL, those are the ones that needs to be looked at. 

From the output of my previous step, I have chosen to use service account named `kustomize-controller` (I am aware that the role assignments to this SP is accurate and maintains least-privilege but this is for illustrating the capabilities of `Kubiscan`).

<pre>

$ <b> kubiscan -aars "kustomize-controller" -ns "flux-system" -k "ServiceAccount" </b>

Roles associated to Subject 'kustomize-controller':
+-------------+-----------+----------------------------+-----------------------------------------------------------------------------+
| Kind        | Namespace | Name                       | Rules                                                                       |
+-------------+-----------+----------------------------+-----------------------------------------------------------------------------+
| ClusterRole | None      | cluster-admin              | (*)->(*)                                                                    |
|             |           |                            | (*)->(None)                                                                 |
|             |           |                            |                                                                             |
| ClusterRole | None      | crd-controller-flux-system | (*)->(*)                                                                    |
|             |           |                            | (*)->(*)                                                                    |
|             |           |                            | (*)->(*)                                                                    |
|             |           |                            | (*)->(*)                                                                    |
|             |           |                            | (*)->(*)                                                                    |
|             |           |                            | (get,list,watch)->(secrets)                                                 |
|             |           |                            | (create,patch)->(events)                                                    |
|             |           |                            | (get,list,watch,create,update,patch,delete)->(configmaps,configmaps/status) |
|             |           |                            | (get,list,watch,create,update,patch,delete)->(leases)                       |
|             |           |                            |                                                                             |
+-------------+-----------+----------------------------+-----------------------------------------------------------------------------+
</pre>

It is now so much more simpler to assess the Roles that are assigned to the Serivce Principals along with their authorization levels. it is interesting to note that a new ClusterRole was created (on top of 51 that K8s cluster gives you) - `crd-controller-flux-system`. Assigning this role to **any** service principal makes the service principal operate in 'God Mode' within the cluster.

## So, what are the remediations?

1. **Protect access to APIs**: No unaudited user or service principal allowed in the cluster

2. **"Proper" Authentication**: If possible use an external identity provider (such as AAD) and integrate with the cluster. With this, you will have safer authentication mechanisms such as MFA for cluster users (although this only protects access to K8s API server, it is still useful)

3. **Limit the blast radius**: If you don't have to use ClusterRole and ClusterRoleBinding, don't use it. In most cases where application deployment is the need, K8s cluster design and administration could use Role and RoleBinding (instead of ClusterRole and ClusterRoleBinding) so if someone wants to use Cluster-level role and bindings, use a bit of 'insult and embarrass' tonic on them.

4. **Admission Control and GitOps**: The best way to ensure 'integrity' of the cluster is to ensure monitored continously, configuration managed and change managed. Sounds lofted but the idea is quite simple - ensure you have a single source of truth that configures the cluster (I am so glad we have Infrastructure-as-code!). Git comes to the rescue with its newest feature Git Workflows. Although this requires a level of operational maturity, this is a true north-star that organizations who intend to use shared cluster should aim for. Microsoft Reference Architecture for [GitOps and Kubernetes](https://docs.microsoft.com/en-us/azure/architecture/example-scenario/gitops-aks/gitops-blueprint-aks) is a great reference to achieve this.
