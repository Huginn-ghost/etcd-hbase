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

import io.etcdhbase.core.auth.AuthSessionException;
import io.etcdhbase.core.auth.AuthorizationRevocation;
import io.etcdhbase.core.bytes.ByteKey;
import io.etcdhbase.core.request.RequestScope;
import io.etcdhbase.hbase.codec.AuthorizationRevocationMessages;
import io.etcdhbase.spi.salt.HashSaltStrategy;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
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

class HBaseAuthorizationRevocationStoreTest {
  private final AuthControlBinding binding = new AuthControlBinding(
      TableName.valueOf("auth_control"), "trust", new HashSaltStrategy());
  private final AsyncConnection connection = mock(AsyncConnection.class);
  private final AsyncTableBuilder<?> builder = mock(AsyncTableBuilder.class, RETURNS_SELF);
  private final AsyncTable<?> table = mock(AsyncTable.class);
  private final HBaseAuthSessionStore store;
  private final AuthorizationRevocation initial = AuthorizationRevocation.start(bytes(1, 16), bytes(2, 32), "provider", "realm", 2, 2, 3,
      List.of(new AuthorizationRevocation.TargetIdentity("group-a", bytes(3, 32), bytes(4, 32)),
          new AuthorizationRevocation.TargetIdentity("group-b", bytes(5, 32), bytes(6, 32))));

  HBaseAuthorizationRevocationStoreTest() {
    doReturn(builder).when(connection).getTableBuilder(binding.table());
    doReturn(table).when(builder).build();
    store = new HBaseAuthSessionStore(connection, binding);
  }

  @Test
  void readsStronglyAndRejectsARecordForAnotherOperation() {
    byte[] row = binding.keyCodec().authorizationRevocation(initial.operationId());
    var wrong = AuthorizationRevocation.start(bytes(7, 16), bytes(2, 32), "provider", "realm", 2, 2, 3,
        initial.targets().stream().map(AuthorizationRevocation.Target::identity).toList());
    doReturn(CompletableFuture.completedFuture(result(row, initial)),
        CompletableFuture.completedFuture(result(row, wrong)),
        CompletableFuture.completedFuture(Result.EMPTY_RESULT)).when(table).get(any(Get.class));
    try (var scope = RequestScope.withoutDeadline()) {
      assertEquals(initial, store.readRevocation(initial.operationId(), scope).toCompletableFuture().join()
          .orElseThrow());
      var failure = assertThrows(CompletionException.class,
          () -> store.readRevocation(initial.operationId(), scope).toCompletableFuture().join());
      assertEquals(AuthSessionException.Reason.DEPENDENCY_UNAVAILABLE,
          assertInstanceOf(AuthSessionException.class, failure.getCause()).reason());
      assertTrue(store.readRevocation(initial.operationId(), scope).toCompletableFuture().join().isEmpty());
      var calls = ArgumentCaptor.forClass(Get.class);
      verify(table, times(3)).get(calls.capture());
      assertTrue(calls.getAllValues().stream().allMatch(value -> value.getConsistency() == Consistency.STRONG));
    }
  }

  @Test
  void onlyCreatesInitialStateAndUsesDurableExactCasForProgress() {
    doReturn(CompletableFuture.completedFuture(new CheckAndMutateResult(true, null)))
        .when(table).checkAndMutate(any(CheckAndMutate.class));
    var assigned = initial.assignBarrier("group-a", 4);
    try (var scope = RequestScope.withoutDeadline()) {
      assertTrue(store.createRevocationIfAbsent(initial, scope).toCompletableFuture().join());
      assertTrue(store.compareAndSetRevocation(initial, assigned, scope).toCompletableFuture().join());
      var calls = ArgumentCaptor.forClass(CheckAndMutate.class);
      verify(table, times(2)).checkAndMutate(calls.capture());
      assertArrayEquals(AuthorizationRevocationMessages.encode(initial), calls.getAllValues().get(1).getValue());
      for (var call : calls.getAllValues()) {
        assertEquals(Durability.SYNC_WAL, assertInstanceOf(Put.class, call.getAction()).getDurability());
      }
      assertThrows(CompletionException.class,
          () -> store.createRevocationIfAbsent(assigned, scope).toCompletableFuture().join());
      assertThrows(CompletionException.class,
          () -> store.compareAndSetRevocation(assigned, initial, scope).toCompletableFuture().join());
    }
  }

  private Result result(byte[] row, AuthorizationRevocation record) {
    return Result.create(new org.apache.hadoop.hbase.Cell[] {
        new KeyValue(row, binding.family(), new byte[] {'r'}, AuthorizationRevocationMessages.encode(record))});
  }

  private static ByteKey bytes(int value, int length) {
    byte[] raw = new byte[length];
    java.util.Arrays.fill(raw, (byte) value);
    return ByteKey.copyOf(raw);
  }
}
