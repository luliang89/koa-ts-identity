'use strict';

import { IUser, IUserStore } from './authenticator';

import redis = require('redis');

export class RedisUserStore implements IUserStore {

    /**
     * async client
     */
    readonly redis: any;

    constructor(
        redisClient: redis.RedisClient
    ) {
        this.redis = getRedisAsyncClient(redisClient);
    }

    async set(key: string, user: IUser, expires: number) {
        if (user) {
            let u: any = user;
            let temp: any = {};
            for (let key in u) {
                if (u[key]) {
                    temp[key] = u[key];
                }
            }
            console.debug('RedisUserStore', temp);
            await this.redis.hmset(key, temp);
        }
        if (expires) {
            await this.redis.expire(key, expires);
        }
    }

    async get(key: string) {
        let user = await this.redis.hgetall(key);
        return user;
    }

    async remove(key: string) {
        await this.redis.del(key);
    }
}

export function getRedisAsyncClient(client: redis.RedisClient) {

    var pass = ['on'];

    var proxy = new Proxy(client, {
        get: function (target: any, prop: any, receiver) {
            var func = target[prop];
            if (typeof func !== 'function') {
                return func;
            }
            if (pass.indexOf(prop) > -1) {
                return func;
            }
            return function (...args: any[]) {
                return new Promise<any>((resolve, reject) => {
                    args.push(function (err: any, obj: any) {
                        if (err) {
                            reject(err);
                        } else {
                            resolve(obj);
                        }
                    });
                    Reflect.apply(func, target, args);
                });
            }
        }
    });

    return proxy;
}