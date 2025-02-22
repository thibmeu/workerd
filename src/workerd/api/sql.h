// Copyright (c) 2017-2022 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

#pragma once

#include <workerd/jsg/jsg.h>
#include <workerd/util/sqlite.h>
#include <workerd/io/compatibility-date.capnp.h>
#include <workerd/io/io-context.h>

namespace workerd::api {

class DurableObjectStorage;

class SqlStorage final: public jsg::Object, private SqliteDatabase::Regulator {
public:
  SqlStorage(SqliteDatabase& sqlite, jsg::Ref<DurableObjectStorage> storage);
  ~SqlStorage();

  using BindingValue = kj::Maybe<kj::OneOf<kj::Array<const byte>, kj::String, double>>;

  class Cursor;
  class Statement;

  jsg::Ref<Cursor> exec(jsg::Lock& js, kj::String query, jsg::Arguments<BindingValue> bindings);

  jsg::Ref<Statement> prepare(jsg::Lock& js, kj::String query);

  double getDatabaseSize();

  JSG_RESOURCE_TYPE(SqlStorage) {
    JSG_METHOD(exec);
    JSG_METHOD(prepare);

    JSG_READONLY_PROTOTYPE_PROPERTY(databaseSize, getDatabaseSize);

    JSG_NESTED_TYPE(Cursor);
    JSG_NESTED_TYPE(Statement);
  }

private:
  void visitForGc(jsg::GcVisitor& visitor) {
    visitor.visit(storage);
  }

  bool isAllowedName(kj::StringPtr name) override;
  bool isAllowedTrigger(kj::StringPtr name) override;
  void onError(kj::StringPtr message) override;
  bool allowTransactions() override;

  IoPtr<SqliteDatabase> sqlite;
  jsg::Ref<DurableObjectStorage> storage;

  kj::Maybe<uint> pageSize;
  kj::Maybe<IoOwn<SqliteDatabase::Statement>> pragmaPageCount;
  kj::Maybe<IoOwn<SqliteDatabase::Statement>> pragmaGetMaxPageCount;

  template <size_t size, typename... Params>
  SqliteDatabase::Query execMemoized(
      kj::Maybe<IoOwn<SqliteDatabase::Statement>>& slot,
      const char (&sqlCode)[size], Params&&... params) {
    // Run a (trusted) statement, preparing it on the first call and reusing the prepared version
    // for future calls.

    SqliteDatabase::Statement* stmt;
    KJ_IF_SOME(s, slot) {
      stmt = &*s;
    } else {
      stmt = &*slot.emplace(IoContext::current().addObject(
          kj::heap(sqlite->prepare(sqlCode))));
    }
    return stmt->run(kj::fwd<Params>(params)...);
  }

  uint64_t getPageSize() {
    KJ_IF_SOME(p, pageSize) {
      return p;
    } else {
      return pageSize.emplace(sqlite->run("PRAGMA page_size;").getInt64(0));
    }
  }
};

class SqlStorage::Cursor final: public jsg::Object {
  class CachedColumnNames;
public:
  template <typename... Params>
  Cursor(Params&&... params)
      : state(IoContext::current().addObject(kj::heap<State>(kj::fwd<Params>(params)...))),
        ownCachedColumnNames(kj::none),  // silence bogus Clang warning on next line
        cachedColumnNames(ownCachedColumnNames.emplace()) {}

  template <typename... Params>
  Cursor(CachedColumnNames& cachedColumnNames, Params&&... params)
      : state(IoContext::current().addObject(kj::heap<State>(kj::fwd<Params>(params)...))),
        cachedColumnNames(cachedColumnNames) {}
  ~Cursor() noexcept(false);

  double getRowsRead();
  double getRowsWritten();

  kj::Array<jsg::JsRef<jsg::JsString>> getColumnNames(jsg::Lock& js);
  JSG_RESOURCE_TYPE(Cursor) {
    JSG_ITERABLE(rows);
    JSG_METHOD(raw);
    JSG_READONLY_PROTOTYPE_PROPERTY(columnNames, getColumnNames);
    JSG_READONLY_PROTOTYPE_PROPERTY(rowsRead, getRowsRead);
    JSG_READONLY_PROTOTYPE_PROPERTY(rowsWritten, getRowsWritten);
  }

  // One value returned from SQL. Note that we intentionally return StringPtr instead of String
  // because we know that the underlying buffer returned by SQLite will be valid long enough to be
  // converted by JSG into a V8 string. For byte arrays, on the other hand, we pass ownership to
  // JSG, which does not need to make a copy.
  using Value = kj::Maybe<kj::OneOf<kj::Array<byte>, kj::StringPtr, double>>;

  using RowDict = jsg::Dict<Value, jsg::JsString>;
  JSG_ITERATOR(RowIterator, rows, RowDict, jsg::Ref<Cursor>, rowIteratorNext);
  JSG_ITERATOR(RawIterator, raw, kj::Array<Value>, jsg::Ref<Cursor>, rawIteratorNext);

private:
  // Helper class to cache column names for a query so that we don't have to recreate the V8
  // strings for every row.
  class CachedColumnNames {
    // TODO(perf): Can we further cache the V8 object layout information for a row?
  public:
    // Get the cached names. ensureInitialized() must have been called previously.
    kj::ArrayPtr<jsg::JsRef<jsg::JsString>> get() { return KJ_REQUIRE_NONNULL(names); }

    void ensureInitialized(jsg::Lock& js, SqliteDatabase::Query& source);

  private:
    kj::Maybe<kj::Array<jsg::JsRef<jsg::JsString>>> names;
  };

  struct State {
      // Refcount on the SqliteDatabase::Statement underlying the query, if any.
    kj::Own<void> dependency;

    // The bindings that were used to construct `query`. We have to keep these alive until the query
    // is done since it might contain pointers into strings and blobs.
    kj::Array<BindingValue> bindings;

    SqliteDatabase::Query query;

    bool isFirst = true;

    State(kj::RefcountedWrapper<SqliteDatabase::Statement>& statement,
          kj::Array<BindingValue> bindings);
    State(SqliteDatabase& db, SqliteDatabase::Regulator& regulator,
          kj::StringPtr sqlCode, kj::Array<BindingValue> bindings);
  };

  // Nulled out when query is done or canceled.
  kj::Maybe<IoOwn<State>> state;

  // True if the cursor was canceled by a new call to the same statement. This is used only to
  // flag an error if the application tries to reuse the cursor.
  bool canceled = false;

  // Reference to a weak reference that might point back to this object. If so, null it out at
  // destruction. Used by Statement to invalidate past cursors when the statement is
  // executed again.
  kj::Maybe<kj::Maybe<Cursor&>&> selfRef;

  // If this cursor was created from a prepared statement, this keeps the statement object alive.
  kj::Maybe<jsg::Ref<Statement>> statement;

  // Row IO counts. These are updated as the query runs. We keep these outside the State so they
  // remain available even after the query is done or canceled.
  uint64_t rowsRead = 0;
  // Row IO counts. These are updated as the query runs. We keep these outside the State so they
  // remain available even after the query is done or canceled.
  uint64_t rowsWritten = 0;

  kj::Maybe<CachedColumnNames> ownCachedColumnNames;
  CachedColumnNames& cachedColumnNames;

  void visitForGc(jsg::GcVisitor& visitor) {
    visitor.visit(statement);
  }

  static kj::Array<const SqliteDatabase::Query::ValuePtr> mapBindings(
      kj::ArrayPtr<BindingValue> values);

  static kj::Maybe<RowDict> rowIteratorNext(jsg::Lock& js, jsg::Ref<Cursor>& obj);
  static kj::Maybe<kj::Array<Value>> rawIteratorNext(jsg::Lock& js, jsg::Ref<Cursor>& obj);
  template <typename Func>
  static auto iteratorImpl(jsg::Lock& js, jsg::Ref<Cursor>& obj, Func&& func)
      -> kj::Maybe<kj::Array<
          decltype(func(kj::instance<State&>(), uint(), kj::instance<Value&&>()))>>;

  friend class Statement;
};

class SqlStorage::Statement final: public jsg::Object {
public:
  Statement(SqliteDatabase::Statement&& statement);

  jsg::Ref<Cursor> run(jsg::Arguments<BindingValue> bindings);

  JSG_RESOURCE_TYPE(Statement) {
    JSG_CALLABLE(run);
  }

private:
  IoOwn<kj::RefcountedWrapper<SqliteDatabase::Statement>> statement;

  // Weak reference to the Cursor that is currently using this statement.
  kj::Maybe<Cursor&> currentCursor;

  // All queries from the same prepared statement have the same column names, so we can cache them
  // on the statement.
  Cursor::CachedColumnNames cachedColumnNames;

  friend class Cursor;
};

#define EW_SQL_ISOLATE_TYPES                    \
  api::SqlStorage,                              \
  api::SqlStorage::Statement,                   \
  api::SqlStorage::Cursor,                      \
  api::SqlStorage::Cursor::RowIterator,         \
  api::SqlStorage::Cursor::RowIterator::Next,   \
  api::SqlStorage::Cursor::RawIterator,         \
  api::SqlStorage::Cursor::RawIterator::Next
// The list of sql.h types that are added to worker.c++'s JSG_DECLARE_ISOLATE_TYPE

}  // namespace workerd::api
