
import {
   CognitoIdentityProviderClient,
   GetUserCommand,
   InitiateAuthCommand,
   InitiateAuthCommandOutput,
   AttributeType,
   ForgotPasswordCommand,
   GlobalSignOutCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import CryptoJS from "crypto-js";

const cognitoClient = new CognitoIdentityProviderClient({
   region: process.env.AWS_REGION || "us-east-1",
});

interface RefreshTokenResult {
   accessToken: string;
   expiresIn: number;
   idToken: string;
}

interface UserInfo {
   name: string;
   email: string;
   id: string;
}

export type { CognitoIdentityProviderClient };
export default cognitoClient;


export const getUserInfo = async (accessToken: string): Promise<UserInfo> => {
   try {
      const command = new GetUserCommand({
         AccessToken: accessToken,
      });

      const response = await cognitoClient.send(command);

      if (!response.UserAttributes) {
         throw new Error("User attributes not found in the response");
      }

      const getAttribute = (name: string): string => {
         return (
            response.UserAttributes?.find(
               (attr: AttributeType) => attr.Name === name
            )?.Value || ""
         );
      };

      return {
         name: getAttribute("name"),
         email: getAttribute("email"),
         id: getAttribute("sub"),
      };
   } catch (error) {
      throw error;
   }
};

export const refreshAccessToken = async (
   refreshToken: string
): Promise<RefreshTokenResult> => {
   if (!process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID) {
      console.error("COGNITO_CLIENT_ID is not set in environment variables");
      throw new Error("COGNITO_CLIENT_ID is not set in environment variables");
   }

   try {
      const command = new InitiateAuthCommand({
         AuthFlow: "REFRESH_TOKEN_AUTH",
         ClientId: process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID,
         AuthParameters: {
            REFRESH_TOKEN: refreshToken,
            CLIENT_ID: process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID,
         },
      });

      const response: InitiateAuthCommandOutput = await cognitoClient.send(
         command
      );

      if (
         !response.AuthenticationResult?.AccessToken ||
         !response.AuthenticationResult.ExpiresIn ||
         !response.AuthenticationResult.IdToken
      ) {
         throw new Error("Invalid response from Cognito");
      }

      return {
         accessToken: response.AuthenticationResult.AccessToken,
         expiresIn: response.AuthenticationResult.ExpiresIn,
         idToken: response.AuthenticationResult.IdToken,
      };
   } catch (error) {
      console.error("Refresh token error:", error);
      throw error;
   }
};

export const forgotPassword = async (username: string): Promise<any> => {
   try {
      const command = new ForgotPasswordCommand({
         ClientId: process.env.NET_PUBLIC_COGNITO_CLIENT_ID,
         Username: username,
      });

      await cognitoClient.send(command);
   } catch (error) {
      console.error("Forgot password error: ", error);
      throw error;
   }
};


export const generateSecretHash = (
   username: string,
   clientSecret: string,
   clientId: string
): string => {
   return CryptoJS.HmacSHA256(username + clientId, clientSecret).toString(CryptoJS.enc.Base64);
};

export const signIn = async (email: string, password: string): Promise<any> => {
   if (!process.env.NEXT_PUBLIC_COGNITO_CLIENT_SECRET || !process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID || !email) {
      throw new Error("Missing required parameters for Cognito authentication.");
   }

   const secretHash = generateSecretHash(email, process.env.NEXT_PUBLIC_COGNITO_CLIENT_SECRET, process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID);
   try {

      const response = await fetch(`https://cognito-idp.us-east-1.amazonaws.com/`, {
         method: "POST",
         headers: {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
         },
         body: JSON.stringify({
            AuthFlow: "USER_PASSWORD_AUTH",
            ClientId: process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID,
            AuthParameters: {
               USERNAME: email,
               PASSWORD: password,
               SECRET_HASH: secretHash,
            },
         }),
      });
      
      if (!response.ok) {
         const error = await response.json();
         throw new Error(error.message || "Authentication failed");
      }
      
      const result = await response.json();
      
      // Return AuthenticationResult
      return result.AuthenticationResult;

      
      // const command = new InitiateAuthCommand({
      //    AuthFlow: "USER_PASSWORD_AUTH",
      //    ClientId: process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID,
      //    AuthParameters: {
      //       USERNAME: email,
      //       PASSWORD: password,
      //       SECRET_HASH: secretHash,
      //    },
      // });

      // const response = await cognitoClient.send(command);
      // return response.AuthenticationResult;

   } catch (error) {
      console.error("Sign in error:", error);
      throw error;
   }
};

export const signOut = async (accessToken: string): Promise<any> => {
   try {
      const command = new GlobalSignOutCommand({
         AccessToken: accessToken,
      });

      await cognitoClient.send(command);
   } catch (error) {
      console.error("Sign out error:", error);
      throw error;
   }
};
