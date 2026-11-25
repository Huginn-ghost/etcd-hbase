package io.etcdhbase.hbase.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import io.etcdhbase.core.auth.AuthConfigurationRecord;
import io.etcdhbase.core.auth.AuthSessionException;
import io.etcdhbase.core.bytes.ByteKey;
import io.etcdhbase.core.error.BackendFailure;
import io.etcdhbase.core.request.RequestScope;
import io.etcdhbase.hbase.codec.AuthMessages;
import io.etcdhbase.spi.salt.HashSaltStrategy;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeoutException;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.TableName;
import org.apache.hadoop.hbase.client.AsyncConnection;
import org.apache.hadoop.hbase.client.AsyncTable;
import org.apache.hadoop.hbase.client.AsyncTableBuilder;
import org.apache.hadoop.hbase.client.CheckAndMutate;
import org.apache.hadoop.hbase.client.CheckAndMutateResult;
import org.apache.hadoop.hbase.client.Consistency;
import org.apache.hadoop.hbase.client.Durability;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class HBaseAuthConfigurationStoreTest {
  private final AuthControlBinding binding = new AuthControlBinding(
      TableName.valueOf("auth_control"), "trust", new HashSaltStrategy());
  private final AsyncConnection connection = mock(AsyncConnection.class);
  private final AsyncTableBuilder<?> builder = mock(AsyncTableBuilder.class, RETURNS_SELF);
  private final AsyncTable<?> table = mock(AsyncTable.class);
  private final HBaseAuthSessionStore store;
  private final AuthConfigurationRecord initial = new AuthConfigurationRecord(
      "trust", "group", ByteKey.copyOf(new byte[32]), true, 1);

  HBaseAuthConfigurationStoreTest() {
    doReturn(builder).when(connection).getTableBuilder(binding.table());
    doReturn(table).when(builder).build();
    store = new HBaseAuthSessionStore(connection, binding);
  }

  @Test
  void readsStronglyAndRejectsRecordsForAnotherGroup() {
    byte[] row = binding.keyCodec().configuration("trust", "group");
    var other = new AuthConfigurationRecord("trust", "other", initial.configurationDigest(), true, 1);
    doReturn(CompletableFuture.completedFuture(result(row, initial)),
        CompletableFuture.completedFuture(result(row, other)),
        CompletableFuture.completedFuture(Result.EMPTY_RESULT)).when(table).get(any(Get.class));
    try (var scope = RequestScope.withoutDeadline()) {
      assertEquals(initial, store.readConfiguration("group", scope).toCompletableFuture().join().orElseThrow());
      assertThrows(CompletionException.class,
          () -> store.readConfiguration("group", scope).toCompletableFuture().join());
      assertTrue(store.readConfiguration("group", scope).toCompletableFuture().join().isEmpty());
      var get = ArgumentCaptor.forClass(Get.class);
      verify(table, times(3)).get(get.capture());
      assertTrue(get.getAllValues().stream().allMatch(value -> value.getConsistency() == Consistency.STRONG));
    }
  }

  @Test
  void creationAndChangesUseExactCasAndRejectRevisionRollback() {
    doReturn(CompletableFuture.completedFuture(new CheckAndMutateResult(true, null)))
        .when(table).checkAndMutate(any(CheckAndMutate.class));
    var next = new AuthConfigurationRecord("trust", "group", ByteKey.copyOf(new byte[32]), false, 2);
    try (var scope = RequestScope.withoutDeadline()) {
      assertTrue(store.createConfigurationIfAbsent(initial, scope).toCompletableFuture().join());
      assertTrue(store.compareAndSetConfiguration(initial, next, scope).toCompletableFuture().join());
      var calls = ArgumentCaptor.forClass(CheckAndMutate.class);
      verify(table, times(2)).checkAndMutate(calls.capture());
      assertArrayEquals(AuthMessages.encode(initial), calls.getAllValues().get(1).getValue());
      for (var call : calls.getAllValues()) {
        assertEquals(Durability.SYNC_WAL, assertInstanceOf(Put.class, call.getAction()).getDurability());
      }
      assertThrows(CompletionException.class,
          () -> store.compareAndSetConfiguration(next, initial, scope).toCompletableFuture().join());
      assertThrows(CompletionException.class,
          () -> store.createConfigurationIfAbsent(next, scope).toCompletableFuture().join());
    }
  }

  @Test
  void corruptConfigurationIsUnavailableWithoutMaskingBackendTimeouts() {
    byte[] row = binding.keyCodec().configuration("trust", "group");
    var other = new AuthConfigurationRecord("trust", "other", initial.configurationDigest(), true, 1);
    var malformed = Result.create(new org.apache.hadoop.hbase.Cell[] {
        new KeyValue(row, binding.family(), new byte[] {'r'}, new byte[] {(byte) 0xff})});
    byte[] wrongRow = binding.keyCodec().configuration("trust", "other");
    doReturn(CompletableFuture.completedFuture(result(row, other)),
        CompletableFuture.completedFuture(malformed),
        CompletableFuture.completedFuture(result(wrongRow, initial)),
        CompletableFuture.failedFuture(new TimeoutException("backend timeout")))
        .when(table).get(any(Get.class));
    try (var scope = RequestScope.withoutDeadline()) {
      for (int index = 0; index < 3; index++) {
        var failure = assertThrows(CompletionException.class,
            () -> store.readConfiguration("group", scope).toCompletableFuture().join());
        assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
            assertInstanceOf(AuthSessionException.class, failure.getCause()).reason());
      }
      var timeout = assertThrows(CompletionException.class,
          () -> store.readConfiguration("group", scope).toCompletableFuture().join());
      assertEquals(BackendFailure.Category.TIMEOUT,
          assertInstanceOf(BackendFailure.class, timeout.getCause()).category());
    }
  }

  private Result result(byte[] row, AuthConfigurationRecord record) {
    return Result.create(new org.apache.hadoop.hbase.Cell[] {
        new KeyValue(row, binding.family(), new byte[] {'r'}, AuthMessages.encode(record))});
  }
}
