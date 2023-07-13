# A Blockchain Consensus Mechanism Based on Verifiable Random Function (VRF)

## Introduction
The traditional Elliptic Curve VRF (ECVRF) is improved by double hashing to increase the level of randomness and thus security, and applied to the consensus forming of consortium blockchain.   
The miner selection process contains two main steps. First, a subset of nodes is selected to be the committee, whose members are all potential miners and can participate in forming a consensus around the next finalized block. An initial finalized block contains a unique and unpredictable identifier that serves as the _alpha_string_ for all nodes. Once an initial block is finalized and the identifier broadcast, each participant uses their private key _sk_ to privately calculate their unique _pi_string_ and ‘random’ _beta_string_. A certain number of nodes with the largest _beta_string_ will make up the committee. The second step is to select the ultimate miner from the committee nodes to generate a new block. The above-mentioned process will be repeated among the committee nodes. Eventually, the node with the largest _beta_string_ will be the miner.   
This strategy offers an alternative to the proof of work approach. Rather than having every participant waste resources on the same puzzle to chase a single prize, a subset of participants are able to co-operate. Adversaries cannot know in advance which subset of participants will ultimately be empowered to elect a miner. Participants themselves have no influence over the _beta_string_ beyond their _sk_. 

## Main Files
`dhvrf.py`: double-hash ECVRF (containing prove and verify functions)  
`election.py`: two functions regarding the selection of committee and the selection of miner  
`blockchain.py`: used Flask to simulate a simple blockchain and nodes  

## Instructions on Running the APP
Enter the following two lines of codes in the terminal，and the APP will be running on _localhost: 5000_.   
```Python
$env:FLASK_APP = "blockchain.py" 
flask run    # The first node, represented by default port 5000  
```
![img.png](Screenshots/img.png)  

Enter the following codes in a new terminal, and then the APP can be running on more ports.   
```Python
$env:FLASK_APP = "blockchain.py"
flask run --port 5001      # Node 2, represented by port 5001
```
![img_1.png](Screenshots/img_1.png)   

Repeat as above.    
```Python
$env:FLASK_APP = "blockchain.py"
flask run --port 5002      # Node 3, represented by port 5002
```
![img_2.png](Screenshots/img_2.png)   

Use _Postman_ to send the information about the three nodes to http://127.0.0.1:5000/new_node. Select "POST".  
After sending, the APP will call the _new_node()_ function in _blockchain.py_ and register the three new nodes.  
![img_3.png](Screenshots/img_3.png)  

Send a piece of transactional information to http://127.0.0.1:5000/new_transactions. Select "POST".  
After sending, the APP will call the _new_transactions()_ function in _blockchain.py_ and store the transaction into the next block of the blockchain.  
![img_4.png](Screenshots/img_4.png)  

Get the election results from http://127.0.0.1:5000/election. Select "GET".  
After sending, the APP will call the _show_election()_ function in _blockchain.py_, and the webpage will show the election results.  
![](Screenshots/img_5.png)  
In the terminal, the entire process of VRF for each node will be shown in detail, including "prove" and "verify" as well as a series of parameters involved.  
![](Screenshots/img_6.png)  

For example, in this experiment the node represented by port 5002 has been selected to be the miner.  
Perform mining at http://127.0.0.1:5002/mine, and get related information. Select "GET".  
![](Screenshots/img_7.png)  

Information about the updated blockchain can be got from http://127.0.0.1:5002/chain. Select "GET".  
Now a newly generated block from the previous mining has been added to the end of the blockchain.  
![](Screenshots/img_8.png)  
However, the blockchain has not been updated on other nodes.
![](Screenshots/img_9.png)  

For Node 1, its blockchain can be updated at http://127.0.0.1:5000/node_refresh. Select "POST".  
![](Screenshots/img_10.png)  
And it is the same for other nodes.
