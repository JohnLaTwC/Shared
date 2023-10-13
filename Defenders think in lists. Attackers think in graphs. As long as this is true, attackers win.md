# Defenders think in lists. Attackers think in graphs. As long as this is true, attackers win.
Date: April 26, 2015

Author: [@JohnLaTwC](https://twitter.com/JohnLaTwC)
## Defender Mindset
A lot of network defense goes wrong before any contact with an adversary, starting with how defenders conceive of the battlefield. Most defenders focus on protecting their assets, prioritizing them, and sorting them by workload and business function. Defenders are awash in lists of assets—in system management services, in asset inventory databases, in BCDR spreadsheets. There's one problem with all of this. Attackers don't have a list of assets—they have a graph. Assets are connected to each other by security relationships. Attackers breach a network by landing somewhere in the graph using a technique such as spearphishing and they hack, finding vulnerable systems by navigating the graph. Who creates this graph? You do.
## What Is the Graph?
The graph in your network is the set of security dependencies that create equivalence classes among your assets. The design of your network, the management of your network, the software and services used on your network, and the behavior of users on your network all influence this graph. Take a domain controller for example. Bob admins the DC from a workstation. If that workstation is not protected as much as the domain controller, the DC can be compromised. Any other account that is an admin on Bob's workstation can compromise Bob and the DC. Every one of those admins logs on to one or more other machines in the natural course of business. If attackers compromise any of them, they have a path to compromise the DC.
## Six Degrees of Mallory
Attackers can lay in wait on a compromised machine, using a password dumper such as mimikatz until a high value account logs on to the machine. Let's examine an example graph.
![alt text](https://github.com/JohnLaTwC/Shared/blob/master/img/DefFigure1.png "Figure 1, Example network logon graph")

The cluster on the left is single Terminal Server used by hundreds of users. If attackers compromise this machine, they can dump the credentials of many users over time.
![alt text](https://github.com/JohnLaTwC/Shared/blob/master/img/DefFigure2.png "Figure 2, A compomised terminal server can lead to many credentials")

How can attackers move laterally to get to the High Value Asset?
![alt text](https://github.com/JohnLaTwC/Shared/blob/master/img/DefFigure3.png "Figure 3, An attack path exists from compromising a terminal server to a high value asset")

By searching the graph, attackers discover multiple paths to the High Value Asset. Compromising the terminal server can allow attackers to also compromise User46 and User128. Those users are admins on Machine2821 and Machine115 respectively. Compromising those workstations allows attackers to compromise User1 and User34, both of which are admins on the High Value Asset. For the High Value Asset to be protected, all the dependent elements must be as protected as thoroughly as the HVA—forming an equivalence class.
## Security Dependencies
In a Windows network, when users perform certain kinds of logons (Interactive, Terminal Server, and others), those users' credentials (and single-sign-on equivalents such as a Kerberos TGT or NTLM hash) are exposed to theft if the underlying host is compromised. Beyond this, there are many kinds of relationships that create security dependencies:
* Local admin accounts with a common password. Compromise one system, dump the local admin password, and use that password on other hosts with the same password.
* File servers housing logon scripts that run for many users and software update servers.
* Print servers that deliver print drivers to client machines when used.
* Certificate authorities that issue certificates valid for smart card logons.
* Database admins that can run code under the context of a database server running as a privileged user.

And so on. There are indirect relations as well. A machine that has a vulnerability can be compromised, suddenly allowing attackers to create new edges in the graph. Or users may have an account in two untrusted domains with the same password, creating a hidden edge between domains.
## Manage your Graph
What can you do as a defender? The first step is to visualize your network by turning your lists into graphs. Next, implement controls to prune the graph:
* Examine unwanted edges that create huge connectivity bursts. Implement infrastructure partitioning and credential silos to reduce them.
* Reduce the number of admins. Use Just-In-Time / Just Enough techniques for privilege minimization.
* Use two factor authentication to mitigate certain edge traversals.
* Apply a solid credential rotation approach in case a user account is compromised.
* Rethink forest trust relationships.
## Learn to Spot List Thinking
Defenders need to ensure that attackers don't have a leg up on them when visualizing the battlefield. In this contest, defenders can have the upper hand. They can have full information about their own network, whereas attackers need to study the network piece by piece. Defenders should take a lesson from how attackers come to understand the graph. Attackers study the infrastructure as it is—not as an inaccurate mental model, viewed from an incomplete asset inventory system, or a dated network diagram. Manage from reality because that's the prepared Defenders Mindset.
## Further Reading
There are a number of papers about attack graphs. Here are a few:

* Heat-ray: Combating Identity Snowball Attacks Using Machine Learning, Combinatorial Optimization and Attack Graph by J. Dunagan, D. Simon, and A. Zheng, http://alicezheng.org/papers/sosp2009-heatray-10pt.pdf
* Two Formal Analyses of Attack Graphs by S. Jha, O. Sheyner and J. Wing, http://www.cs.cmu.edu/~scenariograph/jha-wing.pdf
* Using Model Checking to Analyze Network Vulnerabilities by P. Ammann and R. Ritchey, http://cyberunited.com/wp-content/uploads/2013/03/Using-Model-Checking-to-Analyze-Network-Vulnerabilities.pdf
* A Graph-Based System for Network-Vulnerability Analysis by C. Phillips and L. Swiler, http://web2.utc.edu/~djy471/CPSC4660/graph-vulnerability.pdf
* Automated Generation and Analysis of Attack Graphs by J. Haines, S. Jha, R. Lippman, O. Sheyner, J. Wing, https://www.cs.cmu.edu/~scenariograph/sheyner-wing02.pdf

[And thanks to @4Dgifts for mentioning the two below]
* Modern Intrusion Practices by Gerardo Richarte, https://www.blackhat.com/presentations/bh-usa-03/bh-us-03-richarte.pdf
* Attack Planning in the Real World by Jorge Lucangeli Obes, Gerardo Richarte, Carlos Sarraute, http://arxiv.org/pdf/1306.4044.pdf
