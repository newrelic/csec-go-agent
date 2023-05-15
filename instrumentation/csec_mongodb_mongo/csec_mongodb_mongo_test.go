// Copyright 2023 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package csec_mongodb_mongo

import (
	"context"
	"testing"

	"go.mongodb.org/mongo-driver/bson"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"

	secConfig "github.com/newrelic/csec-go-agent/security_config"
)

var userCollection *mongo.Collection

type TestUser struct {
	ID    primitive.ObjectID `bson:"_id,omitempty"`
	Name  string             `bson:"name,omitempty"`
	Email string             `bson:"email,omitempty"`
}

func ConnectMongoDB(t *testing.T) *mtest.T {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	return mt
}

func TestMongoInsertOneHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		mt.AddMockResponses(mtest.CreateSuccessResponse())

		userData := bson.M{"name": "John", "email": "john.doe@test.com"}
		// userData := TestUser{
		// 	Title:  "The Polyglot Developer",
		// 	Author: "Nic Raboy",
		// 	Tags:   []string{"development", "programming", "coding"},
		// }

		_, err := userCollection.InsertOne(context.Background(), userData)
		if err != nil {
			t.Error(err)
			return
		}
		var expectedData = []secConfig.TestArgs{
			{Parameters: "[map[payload:[map[filter:map[email:john.doe@test.com name:John] options:]] payloadType:insert]]", CaseType: secConfig.NOSQL},
		}

		secConfig.ValidateResult(expectedData, t)
	})
}

func TestMongoInsertManyHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		mt.AddMockResponses(mtest.CreateSuccessResponse())

		userData := []interface{}{
			bson.M{"Name": "John", "Email": "john.doe@test.com"},
			bson.M{"Name": "Kevin", "Email": "kevin.doe@test.com"},
			bson.M{"Name": "Tom", "Email": "tom.doe@test.com"},
		}

		_, err := userCollection.InsertMany(context.Background(), userData)
		if err != nil {
			t.Error(err)
			return
		}
		var expectedData = []secConfig.TestArgs{
			{Parameters: "[map[payload:[map[filter:[map[Email:john.doe@test.com Name:John] map[Email:kevin.doe@test.com Name:Kevin] map[Email:tom.doe@test.com Name:Tom]] options:]] payloadType:insert]]", CaseType: secConfig.NOSQL},
		}

		secConfig.ValidateResult(expectedData, t)
	})
}

func TestMongoFindHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		first := mtest.CreateCursorResponse(1, "test.one", mtest.FirstBatch, bson.D{
			{Key: "_id", Value: primitive.NewObjectID()},
			{Key: "name", Value: "kevin"},
			{Key: "email", Value: "john.doe@test.com"},
		})
		second := mtest.CreateCursorResponse(1, "test.two", mtest.NextBatch, bson.D{
			{Key: "_id", Value: primitive.NewObjectID()},
			{Key: "name", Value: "kevin"},
			{Key: "email", Value: "kevin.bar@test.com"},
		})
		killCursors := mtest.CreateCursorResponse(0, "test.three", mtest.NextBatch)
		mt.AddMockResponses(first, second, killCursors)

		filter := bson.D{{Key: "name", Value: "kevin"}}

		cursor, err := userCollection.Find(context.Background(), filter)
		if err != nil {
			t.Error(err)
			return
		}
		defer cursor.Close(context.Background())

	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:kevin] options:]] payloadType:find]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoFindOneHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		first := mtest.CreateCursorResponse(1, "test.one", mtest.FirstBatch, bson.D{
			{Key: "_id", Value: primitive.NewObjectID()},
			{Key: "name", Value: "kevin"},
			{Key: "email", Value: "john.doe@test.com"},
		})
		mt.AddMockResponses(first)

		filter := bson.D{{Key: "name", Value: "kevin"}}

		var user TestUser

		err := userCollection.FindOne(context.Background(), filter).Decode(&user)
		if err != nil {
			t.Error(err)
			return
		}

	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:kevin] options:]] payloadType:find]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoFindOneAndReplaceHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		first := mtest.CreateCursorResponse(1, "test.one", mtest.FirstBatch, bson.D{
			{Key: "_id", Value: primitive.NewObjectID()},
			{Key: "name", Value: "kevin"},
			{Key: "email", Value: "kevin.doe@test.com"},
		})
		mt.AddMockResponses(first)

		filter := bson.D{{Key: "name", Value: "kevin"}}
		replace := bson.D{{Key: "email", Value: "kevinf@example.com"}}

		var user TestUser

		userCollection.FindOneAndReplace(context.Background(), filter, replace).Decode(&user)
	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:kevin] options:map[email:kevinf@example.com]]] payloadType:update]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoFindOneAndUpdateHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		first := mtest.CreateCursorResponse(1, "test.one", mtest.FirstBatch, bson.D{
			{Key: "_id", Value: primitive.NewObjectID()},
			{Key: "name", Value: "tom"},
			{Key: "email", Value: "tom.doe@test.com"},
		})
		mt.AddMockResponses(first)

		filter := bson.D{{Key: "name", Value: "tom"}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "email", Value: "tomh@example.com"}}}}

		var user TestUser

		userCollection.FindOneAndUpdate(context.Background(), filter, update).Decode(&user)

	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:tom] options:map[$set:map[email:tomh@example.com]]]] payloadType:update]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoFindOneAndDeleteHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		first := mtest.CreateCursorResponse(1, "test.one", mtest.FirstBatch, bson.D{
			{Key: "_id", Value: primitive.NewObjectID()},
			{Key: "name", Value: "tom"},
			{Key: "email", Value: "tom.doe@test.com"},
		})
		mt.AddMockResponses(first)

		filter := bson.D{{Key: "name", Value: "tom"}}

		var user TestUser

		userCollection.FindOneAndDelete(context.Background(), filter).Decode(&user)

	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:tom] options:]] payloadType:delete]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoUpdateOneHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		mt.AddMockResponses(bson.D{
			{Key: "ok", Value: 1},
			{Key: "nModified", Value: 1},
		})

		filter := bson.D{{Key: "name", Value: "tom"}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "email", Value: "tomh@example.com"}}}}

		_, err := userCollection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			t.Error(err)
			return
		}
	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:tom] options:map[$set:map[email:tomh@example.com]]]] payloadType:update]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoUpdateManyHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		mt.AddMockResponses(bson.D{
			{Key: "ok", Value: 1},
			{Key: "nModified", Value: 3},
		})

		filter := bson.D{{Key: "name", Value: "tom"}}
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "gender", Value: "male"}}}}

		_, err := userCollection.UpdateMany(context.Background(), filter, update)
		if err != nil {
			t.Error(err)
			return
		}

	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:tom] options:map[$set:map[gender:male]]]] payloadType:update]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoReplaceOneHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		mt.AddMockResponses(bson.D{
			{Key: "ok", Value: 1},
			{Key: "nModified", Value: 1},
		})

		filter := bson.D{{Key: "name", Value: "kevin"}}
		replace := bson.D{{Key: "location", Value: "India"}}

		_, err := userCollection.ReplaceOne(context.Background(), filter, replace)
		if err != nil {
			t.Error(err)
			return
		}

	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:kevin] options:map[location:India]]] payloadType:update]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoDeleteOneHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		mt.AddMockResponses(bson.D{
			{Key: "ok", Value: 1},
			{Key: "n", Value: 1},
		})

		filter := bson.D{{Key: "name", Value: "kevin"}}

		_, err := userCollection.DeleteOne(context.Background(), filter)
		if err != nil {
			t.Error(err)
			return
		}

	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:kevin] options:]] payloadType:delete]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}

func TestMongoDeleteManyHook(t *testing.T) {
	secConfig.RegisterListener()

	mt := ConnectMongoDB(t)
	defer mt.Close()

	mt.Run("success", func(mt *mtest.T) {
		userCollection = mt.Coll
		mt.AddMockResponses(bson.D{
			{Key: "ok", Value: 1},
			{Key: "n", Value: 3},
		})

		filter := bson.D{{Key: "name", Value: "kevin"}}

		_, err := userCollection.DeleteMany(context.Background(), filter)
		if err != nil {
			t.Error(err)
			return
		}

	})
	var expectedData = []secConfig.TestArgs{
		{Parameters: "[map[payload:[map[filter:map[name:kevin] options:]] payloadType:delete]]", CaseType: secConfig.NOSQL},
	}

	secConfig.ValidateResult(expectedData, t)
}
