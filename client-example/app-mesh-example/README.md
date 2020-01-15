# Venafi Policy Enforcement with Amazon Private CA and AWS App Mesh

In this sample, we walkthrough how we can enforce enterprise security policy for certificate requests for AWS App Mesh deployments.

**NOTE:**  At the time of the writing of this walkthrough, AWS App Mesh only supports TLS on the preview channel. You must use 'us-west-2' as the region when following this guide or you won't be able to complete it.

This walkthrough is a combination of the [general README](https://github.com/Venafi/aws-private-ca-policy-venafi/blob/master/README.md) and the walkthrough on [Configuring TLS with AWS Certificate Manager](https://github.com/aws/aws-app-mesh-examples/blob/master/walkthroughs/tls-with-acm/README.md). We highly suggest you have both of these README.md files open while walking through this.

### Instructions 
We should start by following the main [README](https://github.com/Venafi/aws-private-ca-policy-venafi/blob/master/README.md) in this repository. Go through all the instructions until you reach the "Requesting Certificates" stage.

**Note:** The Amazon Certificate Manager Private CA used for these examples will be same. So please set the root domain for the CA to something you can enforce with the policy set.

Now let's move to the AWS instructions, README found [here](https://github.com/aws/aws-app-mesh-examples/blob/master/walkthroughs/tls-with-acm/README.md). 
Complete step 1 with no changes and complete step 2 by changing the value of the SERVICES_DOMAIN variable so that it will comply with the policy enforced by Venafi. 
**Example:** Policy only allows certs to be authorized for *.example.com domain, be sure to set the SERVICES_DOMAIN to example.com.

Skip step 3, we already set up the PCA in the Venafi based instructions. 

Before we move on to step 4, we need to set the variable CERTIFICATE_ARN with the certificate we want to use. This can be done by running something like this (edit the command to with the right domain, base-url, policy and arn value. For more information go back to the 'Requesting Certificates' section in the Venafi README):
    ```bash
    export CERTIFICATE_ARN=`cli-appmesh.py request --domain "*.example.com" --base-url https://1234abcdzz.execute-api.us-west-2.amazonaws.com/v1/request/ --policy zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz --arn "arn:aws:acm-pca:us-west-2:11122233344:certificate-authority/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" | jq -r .CertificateArn`
    ```

**Note:** Make sure you're running this Python script with Python3 (or it wont work) and that you're in the right folder (/client-example/app-mesh-example/)

If ran correctly you should get your certificate arn returned within the CERTIFICATE_ARN variable. Feel free to check by running: 
```
echo $CERTIFICATE_ARN 
```

If you are requesting a certificate that doesn't fit with the set policies, you will get an error when setting the CERTIFICATE_ARN. You can also check by looking at the value of the variable, if it's an empty string, something went wrong.

Now complete step 4. This will take the Certificate you have created above and apply it to the mesh. 

Now finish it up with step 5. This will allow you to test the app. Congratulations! You app mesh application is now secured with TLS certificates that comply with your enterprises security policy!