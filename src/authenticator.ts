'use strict';

import Koa = require('koa');
import crypto = require('crypto');

export const name = 'identity';

/**
 * 认证
 */
export class Authenticator {

    private context: Koa.Context

    private cookieName: string

    constructor(
        private userStore: IUserStore,
        private option: IAuthenticationOption
    ) {
        this.cookieName = `${option.appName}-${name}`;
    }

    private createUserStoreKey(token: string) {
        return this.cookieName + '-' + token;
    }

    /**
     * 检查请求源，阻止CSRF攻击
     */
    private checkOrigin() {
        let method = this.context.method.toLowerCase();
        if (['post', 'put', 'delete'].indexOf(method) === -1) {
            return;
        }
        let origin: string = this.context.header['origin'];
        if (!origin || !origin.endsWith(this.option.origin)) {
            this.context.throw(400);
        }
    }

    run() {

        var _this = this;

        return async function (context: Koa.Context, next: () => Promise<void>) {
            _this.context = context;
            try {
                _this.checkOrigin();

                let token = context.cookies.get(_this.cookieName);
                context.state.isAuthenticated = false;

                if (token) {
                    token = decodeURIComponent(token);
                    let key = _this.createUserStoreKey(token);
                    let user = await _this.userStore.get(key);
                    if (user) {
                        let u: any = user;
                        _this.userStore.set(key, null, _this.option.expires);
                        context.state.user = u;
                        context.state.isAuthenticated = true;
                    }
                }

                await next();

            } finally {
                _this.context = null;
            }
        }
    }

    async signIn(ctx: Koa.Context, user: IUser) {
        let req = ctx.request;
        let u: any = user;
        u.ip = req.header['x-real-ip'] || req.ip;
        let rand = Math.floor(Math.random() * 1000000);
        let temp = `${req.ip}:${user.id}:${rand}`;
        let token = crypto.createHmac('sha1', this.option.secretKey)
            .update(temp).digest().toString('base64');
        await this.userStore.set(this.createUserStoreKey(token), user, this.option.expires);
        ctx.cookies.set(this.cookieName, token);
    }

    async signOut(ctx: Koa.Context) {
        let token = ctx.cookies.get(this.cookieName);
        await this.userStore.remove(this.createUserStoreKey(token));
        ctx.cookies.set(this.cookieName, '');
    }

}

export interface IAuthenticationOption {

    /**
     * 应用名称
     */
    appName: string

    /**
     * 密匙，用于加密cookie
     */
    secretKey: string

    /**
     * 失效时间，单位秒，用于cookie
     */
    expires: number

    /*
     * 请求源，用于阻止CSRF攻击
     */
    origin: string

}

/**
 * 用户存储库
 */
export interface IUserStore {

    set(key: string, user: IUser, expires: number): Promise<void>;

    get(key: string): Promise<IUser>;

    remove(key: string): Promise<void>;
}

export interface IUser {
    id: string
}