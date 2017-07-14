'use strict';

import 'mocha';
import assert = require('assert');
import Koa = require('koa');

import { Authorization, IRoleValidator, IAuthorizationOption } from '../src/authorization';

class RoleValidator implements IRoleValidator {

    async validate(user: any, roles: string[]) {
        if (!user.roles) {
            return false;
        }
        for (let r of roles) {
            if (user.roles.indexOf(r) < 0) {
                return false;
            }
        }
        return true;
    }

}

var roleValidator = new RoleValidator();

var auth = new Authorization({
    loginUrl: '/login'
}, null, roleValidator);

class Ctrl {
    @auth.authorize()
    add() {
        throw 'add';
    }
}

class Ctrl2 {
    @auth.authorize('r')
    add() {
        throw 'add';
    }
}

@auth.authorize()
class AuthClass {
    add() {
        throw 'add';
    }
}

@auth.authorize('r')
class AuthClass2 {
    add() {
        throw 'add';
    }
}

@auth.authorize()
class AuthCross {

    get() {
        throw 'add';
    }

    @auth.allowAnonymous()
    add() {
        throw 'add';
    }

}

@auth.authorize('r')
class AuthCross2 {

    @auth.allowAnonymous()
    get() {
        throw 'get';
    }

    @auth.authorize('o')
    add() {
        throw 'add';
    }

}

describe('Authorization', function () {

    var ctx: any;

    beforeEach(function () {
        ctx = {
            redirect: function (url: string) {
                throw 'redirect';
            },
            throw: function (status: number) {
                throw status;
            }
        };

    });

    describe('authorize method', function () {

        it('not logged', function (done) {
            ctx.state = {};
            ctx.state.route = {
                controller: Ctrl,
                action: 'add'
            }
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    var ctrl = new Ctrl();
                    try {
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'redirect');
                done();
            });
        });

        it('logged', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name'
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: Ctrl,
                action: 'add'
            }
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    var ctrl = new Ctrl();
                    try {
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'add');
                done();
            });
        });

        it('unauthorized ', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name'
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: Ctrl2,
                action: 'add'
            }
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    var ctrl = new Ctrl2();
                    try {
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, '403');
                done();
            });
        });

        it('authorized ', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name',
                    roles: 'r'
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: Ctrl2,
                action: 'add'
            }
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    var ctrl = new Ctrl2();
                    try {
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'add');
                done();
            });
        });

    });

    describe('authorize class', function () {

        it('not logged', function (done) {
            ctx.state = {};
            ctx.state.route = {
                controller: AuthClass,
                action: 'add'
            }
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    try {
                        var ctrl = new AuthClass();
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'redirect');
                done();
            });
        });

        it('logged', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name'
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: AuthClass,
                action: 'add'
            }
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    try {
                        var ctrl = new AuthClass();
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'add');
                done();
            });
        });

        it('unauthorized', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name'
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: AuthClass2,
                action: 'add'
            }
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    var ctrl = new AuthClass2();
                    try {
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, '403');
                done();
            });
        });

        it('authorized', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name',
                    roles: 'r'
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: AuthClass,
                action: 'add'
            }
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    var ctrl = new AuthClass2();
                    try {
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'add');
                done();
            });
        });

    });

    describe('authorize cross', function () {

        it('not logged allowAnonymous', function (done) {
            ctx.state = {};
            ctx.state.route = {
                controller: AuthCross,
                action: 'add'
            };
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    try {
                        var ctrl = new AuthCross();
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'add');
                done();
            });
        });

        it('not logged', function (done) {
            ctx.state = {};
            ctx.state.route = {
                controller: AuthCross,
                action: 'get'
            };
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    try {
                        var ctrl = new AuthCross();
                        ctrl.get();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'redirect');
                done();
            });
        });

        it('logged allowAnonymous', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name'
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: AuthCross,
                action: 'add'
            };
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    try {
                        var ctrl = new AuthCross();
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'add');
                done();
            });
        });

        it('authorized', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name',
                    roles: ['r', 'o']
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: AuthCross2,
                action: 'add'
            };
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    try {
                        var ctrl = new AuthCross2();
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, 'add');
                done();
            });
        });

        it('unauthorized', function (done) {
            ctx.state = {
                user: {
                    id: 'id',
                    name: 'name',
                    roles: ['r']
                }
            };
            ctx.state.isAuthenticated = true;
            ctx.state.route = {
                controller: AuthCross2,
                action: 'add'
            };
            var next = () => {
                return new Promise<void>((resolve, reject) => {
                    try {
                        var ctrl = new AuthCross2();
                        ctrl.add();
                    } catch (e) {
                        reject(e);
                    }
                    resolve();
                });
            };

            auth.run()(ctx, next).catch(e => {
                assert.equal(e, '403');
                done();
            });
        });

    });

}); 
