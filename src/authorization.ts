'use strict';

import Koa = require('koa');

import { IUser } from './authenticator';

/**
 * 角色验证器
 */
export interface IRoleValidator {

    validate(user: IUser, roles: string[]): Promise<boolean>;

}

/**
 * 用户行为记录器
 */
export interface IUserActionLogger {

    log(context: Koa.Context, roles: string[]): Promise<void>;

}

export interface IAuthorizationOption {

    loginUrl: string

}

class ControllerInfo {

    authClass: boolean = false

    roles?: string[]

    actions = new Map<string, string[]>()

    allowAnonymous = new Set<string>()
}

/**
 * 鉴权
 */
export class Authorization {

    private controllers = new Map<Function, ControllerInfo>();

    constructor(
        private option: IAuthorizationOption,
        private actionLogger?: IUserActionLogger,
        private roleValidator?: IRoleValidator
    ) {

    }

    /**
     * 
     * @param {string[]} roles 角色 
     */
    authorize(...roles: string[]) {
        if (!this.roleValidator && roles && roles.length > 0) {
            throw 'roleValidator is invalid';
        }
        var _this = this;

        return function (target: any, key?: string, descriptor?: TypedPropertyDescriptor<Function>) {
            let controller: Function;
            let isClass = true;
            if (typeof target === 'function' && !key && !descriptor) {
                controller = target;
            } else if (typeof target === 'object' && key && descriptor) {
                controller = target.constructor;
                isClass = false;
            }
            if (controller === undefined) {
                return;
            }
            let info = _this.controllers.get(controller);
            if (!info) {
                info = new ControllerInfo();
                _this.controllers.set(controller, info);
            } else {
                if (isClass && info.authClass) {
                    throw '@authorize can use just once';
                }
            }
            if (isClass) {
                info.authClass = true;
                info.roles = roles;
            } else {
                if (info.actions.has(key)) {
                    throw '@authorize can use just once';
                }
                info.actions.set(key, roles);
            }
        }
    }

    /**
     * 允许匿名访问
     */
    allowAnonymous() {
        var _this = this;
        
        return function (target: Object, key: string, descriptor: TypedPropertyDescriptor<Function>) {
            let controller = target.constructor;
            let info = _this.controllers.get(controller);
            if (!info) {
                info = new ControllerInfo();
                info.allowAnonymous.add(key);
                _this.controllers.set(controller, info);
            } else {
                if (info.allowAnonymous.has(key)) {
                    throw '@allowAnonymous can use just once';
                }
                info.allowAnonymous.add(key);
            }
        }
    }

    run() {
        var _this = this;

        return async function (context: Koa.Context, next: () => Promise<void>) {
            let route = context.state.route;
            if (!route || !route.controller || !route.action) {
                context.throw('the context route is invalid');
            }
            let info = _this.controllers.get(route.controller);
            let allowAnonymous = true;
            let roles: any[];
            if (info) {
                if (info.allowAnonymous.has(route.action) === false) {
                    roles = [];
                    if (info.authClass) {
                        allowAnonymous = false;
                        if (info.roles) {
                            roles = roles.concat(info.roles);
                        }
                    }
                    if (info.actions.has(route.action)) {
                        allowAnonymous = false;
                        let actionRoles = info.actions.get(route.action);
                        if (actionRoles) {
                            roles = roles.concat(actionRoles);
                        }
                    }
                }
            }

            if (allowAnonymous === false) {
                if (!context.state.isAuthenticated) {
                    let url = _this.option.loginUrl + '?redirect=' + context.url;
                    //context.redirect(url);
                    context.body = url;
                    context.status = 401;
                    return;
                }
                if (roles && roles.length > 0) {
                    let success = await _this.roleValidator.validate(context.state.user, roles);
                    if (!success) {
                        context.throw(403);
                    }
                }
            }

            try {
                await next();
            } finally {
                if (_this.actionLogger) {
                    _this.actionLogger.log(context, roles);
                }
            }

        }
    }
}

/** 不依赖koa-ts-route版本
export class Authorization {

    private context: Koa.Context

    private allowAnonymousMap = new Map<Function, Set<string>>();

    constructor(
        private roleValidator: IRoleValidator,
        private option: IAuthorizationOption
    ) {

    }

    authorize(...roles: string[]) {

        if (!this.roleValidator && roles && roles.length > 0) {
            throw 'roleValidator is invalid';
        }
        var _this = this;

        return function (target: any, key?: string, descriptor?: TypedPropertyDescriptor<Function>) {

            if (typeof target === 'function' && !key && !descriptor) {

                return new Proxy(target, {
                    construct: function () {
                        return new Proxy(target.prototype, {
                            get: function (obj: any, key2: string, receiver: any) {
                                let func = obj[key2];
                                if (typeof func !== 'function') {
                                    return func;
                                }
                                let keys = _this.allowAnonymousMap.get(target);
                                if (keys && keys.has(key2)) {
                                    return func;
                                }
                                //console.log(key2, roles);
                                if (_this.validate(roles)) {
                                    return func;
                                }
                                return () => { };
                            }
                        });
                    }
                });
            }

            if (typeof target === 'object' && key && descriptor) {
                var func = descriptor.value;
                descriptor.value = function () {
                    //console.log(key, roles);
                    if (_this.validate(roles)) {
                        return func.apply(this);
                    }
                }
            }

        }
    }

    private validate(roles?: string[]) {
        let user = this.context.state.user;
        if (!user) {
            //this.context.throw(401);
            let url = this.option.loginUrl + '?returnUrl=' + this.context.url;
            this.context.redirect(url);
            return false;
        }
        if (roles && roles.length > 0) {
            let success = this.roleValidator.validate(user, roles);
            if (!success) {
                this.context.throw(403);
            }
        }
        return true;
    }

    allowAnonymous() {
        var _this = this;
        return function (target: Object, key: string, descriptor: TypedPropertyDescriptor<Function>) {
            let keys = _this.allowAnonymousMap.get(target.constructor);
            if (!keys) {
                keys = new Set<string>();
                _this.allowAnonymousMap.set(target.constructor, keys);
            }
            keys.add(key);
        }
    }

    async run(context: Koa.Context, next: () => Promise<void>) {

        this.context = context;

        try {
            await next();
        } finally {
            this.context = null;
        }
    }

}
*/