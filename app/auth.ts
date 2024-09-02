export interface IJWTPayload {
  exp: number;
  iat: number;
  jti: string;
  token_type: 'access' | 'refresh';
  user_id: number;
  identity: {
    username: string;
    groups: Array<{
      description: string;
      id: number;
      is_active: boolean;
      name: string;
      permissions: Array<number>;
    }>;
  };
}

export interface ParsedUserInfo {
  username: string;
  id: number;
  description: string;
  role: string;
  permissions: Array<number>;
  tokenIssueEpoch: number;
  tokenExpEpoch: number;
  token: string;
}

export enum LsKeyNameEnum {
  ACCESS_TOKEN = 'react__access_token',
  REFRESH_TOKEN = 'react__refresh_token',
  ACTIVE_BASE_URL = 'react__active_baseUrl',
  ORIGINAL_BASE_URL = 'react__original_baseUrl',
  THEME = 'react__theme_preference',
}

import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

export class AuthModule {
  parsedUserInfo!: ParsedUserInfo | null;

  set setAccesstoken(token: string) {
    if (Platform.OS === 'web') {
      try {
        if (typeof localStorage !== 'undefined') {
          localStorage.setItem(LsKeyNameEnum.ACCESS_TOKEN, token);
        }
      } catch (e) {
        console.error('Local storage is unavailable:', e);
      }
    } else {
      SecureStore.setItemAsync(
        LsKeyNameEnum.ACCESS_TOKEN,
        JSON.stringify(token),
      );
    }
  }

  get jwtAccesToken(): string | null {
    return localStorage.getItem(LsKeyNameEnum.ACCESS_TOKEN);
  }

  auth() {
    return this.parsedUserInfo;
  }

  parseJwt(token: string): IJWTPayload {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      window
        .atob(base64)
        .split('')
        .map(function (c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join(''),
    );

    return JSON.parse(jsonPayload);
  }

  private setParsedTokenData(token: string) {
    const parsedTokenData = this.parseJwt(token);
    this.parsedUserInfo = {
      id: parsedTokenData?.identity?.groups?.[0]?.id,
      username: parsedTokenData?.identity?.username,
      role: parsedTokenData?.identity?.groups?.[0]?.name,
      token: token,
      description: parsedTokenData?.identity?.groups?.[0]?.description,
      permissions: parsedTokenData?.identity?.groups?.[0]?.permissions,
      tokenIssueEpoch: parsedTokenData?.iat,
      tokenExpEpoch: parsedTokenData?.exp,
    };
  }

  signIn(token: string) {
    if (token) {
      this.setAccesstoken = token;
      this.setParsedTokenData(token);
    }
  }

  signOut() {
    this.parsedUserInfo = null;
    if (Platform.OS === 'web') {
      localStorage.removeItem(LsKeyNameEnum.ACCESS_TOKEN);
    } else {
      SecureStore.deleteItemAsync(LsKeyNameEnum.ACCESS_TOKEN);
    }
  }
}

const Auth = new AuthModule();
export default Auth;
