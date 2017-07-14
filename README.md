# Koa-ts-identity

Koa-ts-identity是基于[Koa-ts-route](https://github.com/luliang89/koa-ts-route)实现身份认证和鉴权的库，使用TypeScript2编写。

## 特点 Features

- 注解
- 完全异步实现
- Redis存储

## 安装 Install

```
$ npm install koa-ts-route
```

## 快速开始 Quick Start

### 初始化 Initialization

```js
//app.ts

import Koa = require('koa');
import { Router, IRoute } from 'koa-ts-route';


import redis2 = require('redis');
import { Authenticator, Authorization, RedisUserStore } from 'koa-ts-identity';

export var koa = new Koa();
export var router = new Router();

var redisClient = redis2.createClient(config.redis);

redisClient.on('error', (err: any) => {
    ...
});

var userStore = new RedisUserStore(redisClient);

export var redis = userStore.redis;

export var authenticator = new Authenticator(userStore, config.authentication);
export var auth = new Authorization(config.url, null, null);

//other koa middleware....

koa.use(router.run());

koa.use(authenticator.run());
koa.use(auth.run());

//other koa middleware....

//last middleware:business code
koa.use(router.execute());

```

### 创建控制器 Create Controller

```js
//order.controller.ts

import { router,auth } from './app';

@auth.authorize()
@router.route()
export class OrderController{
	
    get(){
    	return 'get';
    }
    
    post(){
    	return 'post';
    }
    
    put(){
    	return 'put';
    }
    
    delete(){
    	return 'delete';
    }
    
}
```

### 启动 Start

```js
//index.ts

import { koa } from './app';

import 'order.controller';

koa.listen(3000);

```

GET http://localhost:3000/order -> http 401

POST http://localhost:3000/order -> http 401

....

### 登录 Login

```js
//user.controller.ts

import { authenticator, router } from './app';

@router.route()
export class UserController{
	
    @router.post()
    async login(){
        var user;
    	...
    	await authenticator.signOut(this.context);
        await authenticator.signIn(this.context, user);
    	return user;
    }

}
```

## 部分认证 Part Authenticate

### Use allowAnonymous
```js
@auth.allowAnonymous()
```

### Use @auth.authorize() on the Action
```js
@router.route()
export class UserController{
	
    @auth.authorize()
    async get(){
    	...
    }

}
```

## 授权 Authorization

### Use @auth.authorize()
```
@auth.authorize('admin')
```

### Implements IRoleValidator
```js
//app.ts

import { Authenticator, Authorization, RedisUserStore, IRoleValidator } from 'koa-ts-identity';

export class RoleValidator implements IRoleValidator {
	
    /**
     * user is login user, from authenticator.signIn(this.context, user)
     * roles from @auth.authorize() parameters
     */
    async validate(user: any, roles: string[]) {
    	let result : boolean;
        ...
        return result;
    }

}

export var auth = new Authorization(config.url, null, new RoleValidator());

```

## 用户活动日志 User Action Log

### Implements IUserActionLogger
```js
class UserActionLogger {
	
    /**
     * roles from @auth.authorize() parameters
     */
    async log(ctx: Koa.Context, roles: string[]) {
    	...
	}

}

export var auth = new Authorization(config.url, new UserActionLogger(), new RoleValidator());
```

## License

  MIT