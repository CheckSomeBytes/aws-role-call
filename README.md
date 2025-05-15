```

    ___ _       _______    ____        __        ______      ____
   /   | |     / / ___/   / __ \____  / /__     / ____/___ _/ / /
  / /| | | /| / /\__ \   / /_/ / __ \/ / _ \   / /   / __ `/ / / 
 / ___ | |/ |/ /___/ /  / _, _/ /_/ / /  __/  / /___/ /_/ / / /  
/_/  |_|__/|__//____/  /_/ |_|\____/_/\___/   \____/\__,_/_/_/   
                                                                 
```
AWS Role Call is a Trust Polict Audit tool that reveals external access your AWS Account. 
It does this by grabbing all of the AssumeRole policies assocaited with the roles in your account. It then compares that list to two things: 
1. A community built list of know AWS account ids https://github.com/fwdcloudsec/known_aws_accounts
2. An optional custom file that you can provide that defines your known accounts

The result should show all of the AWS accounts that have access to roles in the environment and specify what vendor they belong to

```
usage: aws-role-call.py [-h] [--profile PROFILE] [-V] [-v] [-f CUSTOM_FILE]

AWS IAM Role Trust Policy Auditor

options:
  -h, --help            show this help message and exit
  --profile PROFILE     AWS CLI profile name
  -V, --superVerbose    moreVerbose
  -v, --verbose         verbose
  -f CUSTOM_FILE, --custom-file CUSTOM_FILE
```



![Screenshot](screenshot.png)
