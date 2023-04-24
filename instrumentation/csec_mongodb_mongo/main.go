// Copyright 2022 New Relic Corporation. All rights reserved.

package csec_mongodb_mongo

import (
	"context"

	secIntercept "github.com/newrelic/csec-go-agent/security_intercept"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var logger = secIntercept.GetLogger("mongohook")

type SecCollection struct {
	mongo.Collection
}

// WrapInterface Hook ------------------------------------
//
//go:noinline
func (coll *SecCollection) secInsertOne_s(ctx context.Context, documents interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error) {
	if secIntercept.IsDisable() {
		return coll.secInsertOne_s(ctx, documents, opts...)
	}
	logger.Debugln("------------ mongoCollectionInsertOne" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if documents != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(documents, ""), "insert")
	}
	a, err := coll.secInsertOne_s(ctx, documents, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return a, err
}

//go:noinline
func (coll *SecCollection) secInsertOne(ctx context.Context, documents interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error) {
	if secIntercept.IsDisable() {
		return coll.secInsertOne_s(ctx, documents, opts...)
	}
	logger.Debugln("------------ mongoCollectionInsertOne" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if documents != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(documents, ""), "insert")
	}
	a, err := coll.secInsertOne_s(ctx, documents, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return a, err
}

//go:noinline
func (coll *SecCollection) secInsertMany_s(ctx context.Context, documents []interface{}, opts ...*options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	if secIntercept.IsDisable() {
		return coll.secInsertMany_s(ctx, documents, opts...)
	}
	logger.Debugln("------------ mongoCollectionInsertMany-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if documents != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(documents, ""), "insert")
	}
	result, err := coll.secInsertMany_s(ctx, documents, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secInsertMany(ctx context.Context, documents []interface{}, opts ...*options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	if secIntercept.IsDisable() {
		return coll.secInsertMany_s(ctx, documents, opts...)
	}
	logger.Debugln("------------ mongoCollectionInsertMany-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if documents != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(documents, ""), "insert")
	}
	result, err := coll.secInsertMany_s(ctx, documents, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secDeleteOne_s(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	if secIntercept.IsDisable() {
		return coll.secDeleteOne_s(ctx, filter, opts...)
	}
	logger.Debugln("------------ mongoCollectionDeleteMany-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, ""), "delete")
	}
	result, err := coll.secDeleteOne_s(ctx, filter, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secDeleteOne(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	if secIntercept.IsDisable() {
		return coll.secDeleteOne_s(ctx, filter, opts...)
	}
	logger.Debugln("------------ mongoCollectionDeleteMany-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, ""), "delete")
	}
	result, err := coll.secDeleteOne_s(ctx, filter, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secDeleteMany_s(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	if secIntercept.IsDisable() {
		return coll.secDeleteMany_s(ctx, filter, opts...)
	}
	logger.Debugln("------------ mongoCollectionDeleteOne-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, ""), "delete")
	}
	result, err := coll.secDeleteMany_s(ctx, filter, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secDeleteMany(ctx context.Context, filter interface{}, opts ...*options.DeleteOptions) (*mongo.DeleteResult, error) {
	if secIntercept.IsDisable() {
		return coll.secDeleteMany_s(ctx, filter, opts...)
	}
	logger.Debugln("------------ mongoCollectionDeleteOne-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, ""), "delete")
	}
	result, err := coll.secDeleteMany_s(ctx, filter, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secUpdateOne_s(ctx context.Context, filter interface{}, update interface{},
	opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	if secIntercept.IsDisable() {
		return coll.secUpdateOne_s(ctx, filter, update, opts...)
	}
	logger.Debugln("------------ mongoCollectionUpdateOne-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil && update != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, update), "update")
	}
	result, err := coll.secUpdateOne_s(ctx, filter, update, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secUpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	if secIntercept.IsDisable() {
		return coll.secUpdateOne_s(ctx, filter, update, opts...)
	}
	logger.Debugln("------------ mongoCollectionUpdateOne-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil && update != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, update), "update")
	}
	result, err := coll.secUpdateOne_s(ctx, filter, update, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secUpdateMany_s(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	if secIntercept.IsDisable() {
		return coll.secUpdateMany_s(ctx, filter, update, opts...)
	}
	logger.Debugln("------------ mongoCollectionUpdateMany-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil && update != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, update), "update")
	}
	result, err := coll.secUpdateMany_s(ctx, filter, update, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secUpdateMany(ctx context.Context, filter interface{}, update interface{}, opts ...*options.UpdateOptions) (*mongo.UpdateResult, error) {
	if secIntercept.IsDisable() {
		return coll.secUpdateMany_s(ctx, filter, update, opts...)
	}
	logger.Debugln("------------ mongoCollectionUpdateMany-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil && update != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, update), "update")
	}
	result, err := coll.secUpdateMany_s(ctx, filter, update, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secReplaceOne_s(ctx context.Context, filter interface{}, replacement interface{}, opts ...*options.ReplaceOptions) (*mongo.UpdateResult, error) {
	if secIntercept.IsDisable() {
		return coll.secReplaceOne_s(ctx, filter, replacement, opts...)
	}
	logger.Debugln("------------ mongoCollectionReplaceOne-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil && replacement != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, replacement), "update")
	}
	result, err := coll.secReplaceOne_s(ctx, filter, replacement, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secReplaceOne(ctx context.Context, filter interface{}, replacement interface{}, opts ...*options.ReplaceOptions) (*mongo.UpdateResult, error) {
	if secIntercept.IsDisable() {
		return coll.secReplaceOne_s(ctx, filter, replacement, opts...)
	}
	logger.Debugln("------------ mongoCollectionReplaceOne-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil && replacement != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, replacement), "update")
	}
	result, err := coll.secReplaceOne_s(ctx, filter, replacement, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return result, err
}

//go:noinline
func (coll *SecCollection) secFind_s(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (*mongo.Cursor, error) {
	if secIntercept.IsDisable() {
		return coll.secFind_s(ctx, filter, opts...)
	}
	logger.Debugln("------------ mongoCollectionFind-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, ""), "find")
	}
	cur, err := coll.secFind_s(ctx, filter, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return cur, err
}

//go:noinline
func (coll *SecCollection) secFind(ctx context.Context, filter interface{}, opts ...*options.FindOptions) (*mongo.Cursor, error) {
	if secIntercept.IsDisable() {
		return coll.secFind_s(ctx, filter, opts...)
	}
	logger.Debugln("------------ mongoCollectionFind-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, ""), "find")
	}
	cur, err := coll.secFind_s(ctx, filter, opts...)
	secIntercept.SendExitEvent(eventID, err)
	return cur, err
}

//go:noinline
func (coll *SecCollection) findOneAndDelete_s(ctx context.Context, filter interface{}, opts ...*options.FindOneAndDeleteOptions) *mongo.SingleResult {
	if secIntercept.IsDisable() {
		return coll.findOneAndDelete_s(ctx, filter, opts...)
	}
	logger.Debugln("------------ mongoCollectionFindOneDelete-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, ""), "delete")
	}
	result := coll.findOneAndDelete_s(ctx, filter, opts...)
	if result != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return result
}

//go:noinline
func (coll *SecCollection) findOneAndDelete(ctx context.Context, filter interface{}, opts ...*options.FindOneAndDeleteOptions) *mongo.SingleResult {
	if secIntercept.IsDisable() {
		return coll.findOneAndDelete_s(ctx, filter, opts...)
	}
	logger.Debugln("------------mongoCollectionFindOneDelete-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, ""), "delete")
	}
	result := coll.findOneAndDelete_s(ctx, filter, opts...)
	if result != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return result
}

//go:noinline
func (coll *SecCollection) secFindOneAndReplace_s(ctx context.Context, filter interface{}, replacement interface{}, opts ...*options.FindOneAndReplaceOptions) *mongo.SingleResult {
	if secIntercept.IsDisable() {
		return coll.secFindOneAndReplace_s(ctx, filter, replacement, opts...)
	}
	logger.Debugln("------------ mongoCollectionFindOneReplace-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, replacement), "update")
	}
	result := coll.secFindOneAndReplace_s(ctx, filter, replacement, opts...)
	if result != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return result
}

//go:noinline
func (coll *SecCollection) secFindOneAndReplace(ctx context.Context, filter interface{}, replacement interface{}, opts ...*options.FindOneAndReplaceOptions) *mongo.SingleResult {
	if secIntercept.IsDisable() {
		return coll.secFindOneAndReplace_s(ctx, filter, replacement, opts...)
	}
	logger.Debugln("------------ mongoCollectionFindOneReplace-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, replacement), "update")
	}
	result := coll.secFindOneAndReplace_s(ctx, filter, replacement, opts...)
	if result != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return result
}

//go:noinline
func (coll *SecCollection) secFindOneAndUpdate_s(ctx context.Context, filter interface{}, update interface{}, opts ...*options.FindOneAndUpdateOptions) *mongo.SingleResult {
	if secIntercept.IsDisable() {
		return coll.secFindOneAndUpdate_s(ctx, filter, update, opts...)
	}
	logger.Debugln("------------mongoCollectionFindOneUpdate-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, update), "update")
	}
	result := coll.secFindOneAndUpdate_s(ctx, filter, update, opts...)
	if result != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return result
}

//go:noinline
func (coll *SecCollection) secFindOneAndUpdate(ctx context.Context, filter interface{}, update interface{}, opts ...*options.FindOneAndUpdateOptions) *mongo.SingleResult {
	if secIntercept.IsDisable() {
		return coll.secFindOneAndUpdate_s(ctx, filter, update, opts...)
	}
	logger.Debugln("------------mongoCollectionFindOneUpdate-hook" + "in hook")
	var eventID = secIntercept.GetDummyEventTracker()
	if filter != nil {
		eventID = secIntercept.TraceMongoOperation(getParam(filter, update), "update")
	}
	result := coll.secFindOneAndUpdate_s(ctx, filter, update, opts...)
	if result != nil {
		secIntercept.SendExitEvent(eventID, nil)
	}
	return result
}

func getParam(f, g interface{}) []byte {
	tmp_map := map[string]interface{}{
		"filter":  f,
		"options": g,
	}
	map_json, err := bson.MarshalExtJSON(tmp_map, true, true)
	if err != nil {
		logger.Errorln("Error During MarshalExtJSON ", tmp_map)
		return []byte("")
	} else {
		return map_json
	}
}

var traceMongoHook error

func traceMongoHookError(name string, e error) {
	secIntercept.IsHookedLog(name, e)
	if e != nil {
		traceMongoHook = e
	}
}

func PluginStart() {

	//insert
	e := secIntercept.HookWrapInterface((*mongo.Collection).InsertMany, (*SecCollection).secInsertMany, (*SecCollection).secInsertMany_s)
	traceMongoHookError("(*mongo.Collection).InsertMany", e)

	e = secIntercept.HookWrapInterface((*mongo.Collection).InsertOne, (*SecCollection).secInsertOne, (*SecCollection).secInsertOne_s)
	traceMongoHookError("(*mongo.Collection).InsertOne", e)
	//find
	e = secIntercept.HookWrapInterface((*mongo.Collection).Find, (*SecCollection).secFind, (*SecCollection).secFind_s)
	traceMongoHookError("(*mongo.Collection).Find", e)
	e = secIntercept.HookWrapInterface((*mongo.Collection).FindOneAndReplace, (*SecCollection).secFindOneAndReplace, (*SecCollection).secFindOneAndReplace_s)
	traceMongoHookError("(*mongo.Collection).FindOneAndReplace", e)
	e = secIntercept.HookWrapInterface((*mongo.Collection).FindOneAndUpdate, (*SecCollection).secFindOneAndUpdate, (*SecCollection).secFindOneAndUpdate_s)
	traceMongoHookError("(*mongo.Collection).FindOneAndUpdate", e)
	e = secIntercept.HookWrapInterface((*mongo.Collection).FindOneAndDelete, (*SecCollection).findOneAndDelete, (*SecCollection).findOneAndDelete_s)
	traceMongoHookError("(*mongo.Collection).FindOneAndDelete", e)

	//update
	e = secIntercept.HookWrapInterface((*mongo.Collection).UpdateOne, (*SecCollection).secUpdateOne, (*SecCollection).secUpdateOne_s)
	traceMongoHookError("(*mongo.Collection).UpdateOne", e)
	e = secIntercept.HookWrapInterface((*mongo.Collection).UpdateMany, (*SecCollection).secUpdateMany, (*SecCollection).secUpdateMany_s)
	traceMongoHookError("(*mongo.Collection).UpdateMany", e)

	//ReplaceOne
	e = secIntercept.HookWrapInterface((*mongo.Collection).ReplaceOne, (*SecCollection).secReplaceOne, (*SecCollection).secReplaceOne_s)
	traceMongoHookError("(*mongo.Collection).ReplaceOne", e)

	// Delete
	e = secIntercept.HookWrapInterface((*mongo.Collection).DeleteOne, (*SecCollection).secDeleteOne, (*SecCollection).secDeleteOne_s)
	traceMongoHookError("(*mongo.Collection).DeleteOne", e)
	e = secIntercept.HookWrapInterface((*mongo.Collection).DeleteMany, (*SecCollection).secDeleteMany, (*SecCollection).secDeleteMany_s)
	traceMongoHookError("(*mongo.Collection).DeleteMany", e)

	secIntercept.TraceMongoHooks(e)
}
func init() {
	if !secIntercept.IsAgentInitializedForHook() || secIntercept.IsForceDisable() || !secIntercept.IsHookingoIsSupported() {
		return
	}
	PluginStart()
}
