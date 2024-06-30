# Network-Intrusions-Detection

Business Objective:< br/>
With the enormous growth of computer networks usage and the huge increase in the number of applications running on top of it, network security is becoming increasingly more important. All the computer systems suffer from security vulnerabilities which are both technically difficult and economically costly to be solved by the manufacturers. Therefore, the role of Intrusion Detection Systems (IDSs), as special-purpose devices to detect anomalies and attacks in the network, is becoming more important.< br/>
The research in the intrusion detection field has been mostly focused on anomaly-based and misusebased detection techniques for a long time. While misuse-based detection is generally favoured in commercial products due to its predictability and high accuracy, in academic research anomaly detection is typically conceived as a more powerful method due to its theoretical potential for addressing novel attacks.< br/>
As part of this project, your task is to build network intrusion detection system to detect anomalies and attacks in the network.< br/>
There are two problems:< br/>
Binomial classification: Detect anomalies by predicting Activity is normal or attack< br/>
Multinomial Classification: Detecting type of activity by predicting Activity is Normal or Back or
Buffer Over flow or FTP Write or Guess Password or Neptune or N-Map or Port Sweep or Root Kit or
Satan or Smurf< br/>

Available Data:< br/>
Organization captured the data over the period of time for different types of attacks and provided the data in different files for different type of activities along with normal.< br/>
Tables: There are 10 tables for different type of attacks with same columns< br/>
  a. Data_of_Attack_Back_Normal
  b. Data_of_Attack_Back
  c. Data_of_Attack_Back_BufferOverflow
  d. Data_of_Attack_Back_FTPWrite
  e. Data_of_Attack_Back_GuessPassword
  f. Data_of_Attack_Back_Neptune
  g. Data_of_Attack_Back_NMap
  h. Data_of_Attack_Back_PortSweep
  i. Data_of_Attack_Back_RootKit
  j. Data_of_Attack_Back_Satan
  k. Data_of_Attack_Back_Smurf


BASIC FEATURES OF EACH NETWORK CONNECTION VECTOR<br />
  1 Duration: Length of time duration of the connection
  2 Protocol_type: Protocol used in the connection
  3 Service: Destination network service used
  4 Flag: Status of the connection –Normal or Error
  5 Src_bytes: Numberof data bytes transferred from source to destination in single connection
  6 Dst_bytes: Numberof data bytes transferred from destination to source in single connection
  7 Land: if source and destination IP addresses and port numbers are equal then, this variable takes value 1 else 0
  8 Wrong_fragment: Total numberof wrong fragments in this connection
  9 Urgent: Numberof urgent packets in this connection. Urgent packets are packets with the urgent bit activated
CONTENT RELATED FEATURES OF EACH NETWORK CONNECTION VECTOR<br />
  10 Hot: Numberof „hot‟ indicators in the contentsuch as: entering a system directory, creating programs and executing programs
  11 Num_failed _logins: Count of failed login attempts
  12 Logged_in Login Status: 1 if successfully logged in; 0 otherwise
  13 Num_compromised: Number of 'compromised' conditions
  14 Root_shell: 1 if root shell is obtained; 0 otherwise
  15 Su_attempted: 1 if 'su root' command attempted orused; 0 otherwise
  16 Num_root: Number of 'root' accesses or numberof operations performed as a root in the connection
  17 Num_file_creations: Number of file creation operations in the connection
  18 Num_shells: Number of shell prompts
  19 Num_access_files: Number of operations on access control files
  20 Num_outbound_cmds: Number of outbound commands in an ftp session
  21 Is_hot_login: 1 if the login belongs to the 'hot' list i.e., root or admin; else 0
  22 Is_guest_login: 1 if the login is a 'guest' login; 0 otherwise
TIME RELATED TRAFFIC FEATURES OF EACH NETWORKCONNECTION VECTOR<br />
  23 Count: Numberof connections to the same destination host as the current connection in the  past two seconds
  24 Srv_count: Numberof connections to the same service (port number) as the current connection in the past two seconds
  25 Serror_rate: The percentage of connectionsthat have activated the flag (4) s0, s1, s2 or s3, among the connections aggregated in count (23)
  26 Srv_serror_rate: The percentage of connectionsthat have activated the flag (4) s0, s1, s2 or s3, among the connections aggregated in srv_count (24)
  27 Rerror_rate: The percentage of connectionsthat have activated the flag (4) REJ, among the connections aggregated in count (23)
  28 Srv_rerror_rate: The percentage of connectionsthat have activated the flag (4) REJ, among the connections aggregated in srv_count (24)
  29 Same_srv_rate: The percentage of connections that were to the same service, among the connections aggregated in count (23)
  30 Diff_srv_rate: The percentage of connections that were to differentservices, among the connections aggregated in count (23)
  31 Srv_diff_host_ rate: The percentage of connections that were to different destination machines among the connections aggregated in srv_count (24)
HOST BASED TRAFFIC FEATURES IN A NETWORK CONNECTION VECTOR<br />
  32 Dst_host_count: Numberof connections having the same destination host IP address
  33 Dst_host_srv_ count: Numberof connections having the same port number
  34 Dst_host_same _srv_rate: The percentage of connectionsthat were to the same service, among the connections aggregated in dst_host_count (32)
  35 Dst_host_diff_ srv_rate: The percentage of connections that were to differentservices, among the connections aggregated in dst_host_count (32)
  36 Dst_host_same _src_port_rate: The percentage of connections that were to the same source port, among the connections aggregated in dst_host_srv_count (33)  
  37 Dst_host_srv_ diff_host_rate: The percentage of connections that were to different destination machines, among the connections aggregated in dst_host_srv_count (33)
  38 Dst_host_serro r_rate: The percentage of connections that have activated the flag (4) s0, s1, s2 or s3, among the connections aggregated in dst_host_count (32)
  39 Dst_host_srv_s error_rate: The percent of connections that have activated the flag (4) s0, s1, s2 or s3, among the connections aggregated in dst_host_srv_count (33)
  40 Dst_host_rerror_rate: The percentage of connectionsthat have activated the flag (4) REJ, among the connections aggregated in dst_host_count (32)
  41 Dst_host_srv_rerror_rate: The percentage of connectionsthat have activated the flag (4) REJ, among the connections aggregated in dst_host_srv_count (33)
  
Type Features:<br />
Nominal: Protocol_type(2), Service(3), Flag(4)
Binary: Land(7), logged_in(12), root_shell(14), su_attempted(15), is_host_login(21), is_guest_login(22)
Numeric: Duration(1), src_bytes(5), dst_bytes(6), wrong_fragment(8), urgent(9), hot(10), num_failed_logins(11), num_compromised(13), num_root(16), num_file_creations(17), num_shells(18), num_access_files(19), num_outbound_cmds(20), count(23), srv_count(24), error_rate(25), srv_serror_rate(26), rerror_rate(27),srv_rerror_rate(28), same_srv_rate(29), diff_srv_rate(30), srv_diff_host_rate(31), dst_host_count(32), dst_host_srv_count(33), dst_host_same_srv_rate(34), dst_host_diff_srv_rate(35), dst_host_same_src_port_rate(36), dst_host_srv_diff_host_rate(37), dst_host_serror_rate(38), dst_host_srv_serror_rate(39), dst_host_rerror_rate(40), dst_host_srv_rerror_rate(41)


Hints about Data: Different attack data set have different number of observations. This data is an  example of imbalance data.


Data Preparation:
You are required to append all the files and create new column called attack based on the name of
attack. While you are appending the files, you can take resampling of data based on the number of attacks.

For Binomial classification, you can create attack variable with attack vs. normal

For Multinomial classification, you can create attack variable with normal vs. Back vs. Buffer Over flow vs. FTP Write vs. Guess Password vs. Neptune vs. N-Map vs. Port Sweep vs. Root Kit vs. Satan vs. Smurf
