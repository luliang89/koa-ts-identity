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

                let token = _this.getTokenByCookie(context);
                context.state.isAuthenticated = false;

                if (token) {
                    let key = _this.createUserStoreKey(token);
                    let user = await _this.getUser(key);
                    if (user) {
                        let nowTimes = new Date().getTime();
                        if (nowTimes > user.expires) {
                            context.state.user = null;
                            context.state.isAuthenticated = false;
                        } else {
                            user.expires += _this.option.expires * 1000;
                            context.state.isAuthenticated = true;
                        }
                        _this.userStore.set(key, user);
                        context.state.user = user;
                    }
                } else {
                    let token = await _this.calculateToken(context);
                    let now = new Date();
                    now.setFullYear(now.getFullYear() + 10);
                    context.cookies.set(this.cookieName, token, {
                        expires: now
                    });
                }

                await next();

            } finally {
                _this.context = null;
            }
        }
    }

    getIP(ctx: Koa.Context) {
        return ctx.request.header['x-real-ip'] || ctx.request.ip;
    }

    getTokenByCookie(ctx: Koa.Context) {
        let token = ctx.cookies.get(this.cookieName);
        if (token) {
            token = decodeURIComponent(token);
        }
        return token;
    }

    async getUser(token: string) {
        let key = this.createUserStoreKey(token);
        let user = await this.userStore.get(key);
        return user;
    }

    async setUser(token: string, user: IUser) {
        let key = this.createUserStoreKey(token);
        await this.userStore.set(this.createUserStoreKey(token), user);
    }

    async calculateToken(ctx: Koa.Context) {
        let req = ctx.request;
        let ip = this.getIP(ctx);
        let userAgent = req.header['user-agent'];
        let rand = Math.floor(Math.random() * 1000000);
        let temp = `${ip}:${userAgent}:${rand}`;
        let token = crypto.createHmac('sha1', this.option.secretKey)
            .update(temp).digest().toString('base64');
        return token;
    }

    /** 
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
    */

    async signIn(ctx: Koa.Context, user: IUser) {
        let ip = this.getIP(ctx);
        user.ip = ip;
        let now = new Date().getTime();
        now += this.option.expires * 1000;
        user.expires = now;
        let token = this.getTokenByCookie(ctx);
        await this.setUser(token, user);
    }

    async signOut(ctx: Koa.Context) {
        let token = this.getTokenByCookie(ctx);
        let user = await this.getUser(token);
        if (user) {
            user.expires = 0;
            await this.setUser(token, user);
        }
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
     * 失效时间，单位秒，用户登录有效期
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

    set(key: string, user: IUser): Promise<void>;

    get(key: string): Promise<IUser>;

    remove(key: string): Promise<void>;
}

export interface IUser {

    [k: string]: any

    id: string
}