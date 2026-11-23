import test from "node:test";
import assert from "node:assert/strict";
import {SessionStore,createCookie,verifyCookie} from "../src/session.js";

test("expired sessions disappear",()=>{const s=new SessionStore();const x=s.create("demo",100,1000);assert.ok(s.get(x.id,1050));assert.equal(s.get(x.id,1100),null);});
test("tampered cookies fail",()=>{const c=createCookie("abc","secret",60);assert.equal(verifyCookie(c,"secret"),"abc");assert.equal(verifyCookie(c.replace("abc","xyz"),"secret"),null);});
