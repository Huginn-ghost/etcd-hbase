package io.etcdhbase.hbase.storage;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.etcdhbase.core.auth.DeploymentControlRecord;
import io.etcdhbase.core.auth.DeploymentIdentity;
import io.etcdhbase.core.bytes.ByteKey;
import io.etcdhbase.core.error.BackendFailure;
import io.etcdhbase.core.request.RequestScope;
import io.etcdhbase.hbase.codec.DeploymentControlMessages;
import io.etcdhbase.spi.salt.HashSaltStrategy;
import java.util.List;
import java.util.Optional;
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

class HBaseDeploymentControlStoreTest {
  private final AuthControlBinding binding = new AuthControlBinding(
      TableName.valueOf("auth_control"), "trust", new HashSaltStrategy());
  private final DeploymentIdentity identity = new DeploymentIdentity("trust", "group",
      ByteKey.copyOf(new byte[32]), 1, "instance");
  private final DeploymentControlRecord active = new DeploymentControlRecord(
      DeploymentControlRecord.Kind.BINDING_V1, identity, 1, DeploymentControlRecord.State.ACTIVE,
      Optional.empty(), ByteKey.copyOf(new byte[] {1}));
  private final AsyncConnection connection = mock(AsyncConnection.class);
  private final AsyncTableBuilder<?> builder = mock(AsyncTableBuilder.class, RETURNS_SELF);
  private final AsyncTable<?> table = mock(AsyncTable.class);
  private final HBaseDeploymentControlStore store;

  HBaseDeploymentControlStoreTest() {
    doReturn(builder).when(connection).getTableBuilder(binding.table());
    doReturn(table).when(builder).build();
    store = new HBaseDeploymentControlStore(connection, binding);
  }

  @Test
  void readsTheExactBindingStronglyAndRejectsMissingOrCorruptValues() {
    byte[] row = binding.keyCodec().deploymentBindingV1(identity.bindingDigest());
    byte[] qualifier = binding.keyCodec().deploymentBindingQualifierV1(identity.bindingDigest());
    byte[] value = DeploymentControlMessages.encode(active);
    Result valid = Result.create(new org.apache.hadoop.hbase.Cell[] {
        new KeyValue(row, binding.family(), qualifier, value)});
    byte[] corrupted = value.clone();
    corrupted[corrupted.length - 1] ^= 1;
    Result invalid = Result.create(new org.apache.hadoop.hbase.Cell[] {
        new KeyValue(row, binding.family(), qualifier, corrupted)});
    doReturn(CompletableFuture.completedFuture(valid), CompletableFuture.completedFuture(Result.EMPTY_RESULT),
        CompletableFuture.completedFuture(invalid)).when(table).get(any(Get.class));
    try (var scope = RequestScope.withoutDeadline()) {
      assertEquals(active, store.readRequired(active.kind(), identity, Optional.empty(), scope)
          .toCompletableFuture().join());
      var get = ArgumentCaptor.forClass(Get.class);
      verify(table).get(get.capture());
      assertEquals(Consistency.STRONG, get.getValue().getConsistency());
      assertArrayEquals(row, get.getValue().getRow());
      assertTrue(get.getValue().getFamilyMap().get(binding.family()).contains(qualifier));
      assertThrows(CompletionException.class, () -> store.readRequired(active.kind(), identity,
          Optional.empty(), scope).toCompletableFuture().join());
      assertThrows(CompletionException.class, () -> store.readRequired(active.kind(), identity,
          Optional.empty(), scope).toCompletableFuture().join());
    }
  }

  @Test
  void createAndCasUseExactValuesAndSyncWalWithoutReactivatingTombstones() {
    doReturn(CompletableFuture.completedFuture(new CheckAndMutateResult(true, null)),
        CompletableFuture.completedFuture(new CheckAndMutateResult(false, null)))
        .when(table).checkAndMutate(any(CheckAndMutate.class));
    ByteKey operation = ByteKey.copyOf(new byte[16]);
    var revoking = new DeploymentControlRecord(active.kind(), identity, 2,
        DeploymentControlRecord.State.REVOKING, Optional.of(operation), active.payload());
    var revoked = new DeploymentControlRecord(active.kind(), identity, 3,
        DeploymentControlRecord.State.REVOKED, Optional.of(operation), active.payload());
    try (var scope = RequestScope.withoutDeadline()) {
      assertTrue(store.createIfAbsent(active, scope).toCompletableFuture().join());
      assertFalse(store.compareAndSet(active, revoking, scope).toCompletableFuture().join());
      var calls = ArgumentCaptor.forClass(CheckAndMutate.class);
      verify(table, org.mockito.Mockito.times(2)).checkAndMutate(calls.capture());
      assertArrayEquals(DeploymentControlMessages.encode(active), calls.getAllValues().get(1).getValue());
      for (CheckAndMutate call : calls.getAllValues()) {
        assertEquals(Durability.SYNC_WAL, assertInstanceOf(Put.class, call.getAction()).getDurability());
      }
      assertThrows(CompletionException.class, () -> store.compareAndSet(revoked, active, scope)
          .toCompletableFuture().join());
      assertThrows(CompletionException.class, () -> store.createIfAbsent(revoked, scope)
          .toCompletableFuture().join());
    }
  }

  @Test
  void rejectsARecordForAnotherDatasetAndDoesNotTreatUnknownCasAsSuccess() {
    byte[] row = binding.keyCodec().deploymentBindingV1(identity.bindingDigest());
    byte[] qualifier = binding.keyCodec().deploymentBindingQualifierV1(identity.bindingDigest());
    byte[] otherDataset = new byte[32];
    otherDataset[0] = 1;
    var otherIdentity = new DeploymentIdentity("trust", "group", ByteKey.copyOf(otherDataset), 1, "instance");
    var other = new DeploymentControlRecord(active.kind(), otherIdentity, 1,
        DeploymentControlRecord.State.ACTIVE, Optional.empty(), active.payload());
    doReturn(CompletableFuture.completedFuture(Result.create(new org.apache.hadoop.hbase.Cell[] {
        new KeyValue(row, binding.family(), qualifier, DeploymentControlMessages.encode(other))})))
        .when(table).get(any(Get.class));
    doReturn(CompletableFuture.failedFuture(new BackendFailure(BackendFailure.Category.TIMEOUT)))
        .when(table).checkAndMutate(any(CheckAndMutate.class));
    var revoking = new DeploymentControlRecord(active.kind(), identity, 2,
        DeploymentControlRecord.State.REVOKING, Optional.of(ByteKey.copyOf(new byte[16])), active.payload());
    try (var scope = RequestScope.withoutDeadline()) {
      assertThrows(CompletionException.class, () -> store.readRequired(active.kind(), identity,
          Optional.empty(), scope).toCompletableFuture().join());
      var failure = assertThrows(CompletionException.class, () -> store.compareAndSet(active, revoking, scope)
          .toCompletableFuture().join());
      assertEquals(BackendFailure.Category.TIMEOUT,
          assertInstanceOf(BackendFailure.class, failure.getCause()).category());
    }
  }

  @Test
  void operationReadsUseTheExactPersistentOperationIdentity() {
    ByteKey operationId = ByteKey.copyOf(new byte[16]);
    var pending = new DeploymentControlRecord(DeploymentControlRecord.Kind.REVOCATION_V1,
        identity, 1, DeploymentControlRecord.State.REVOKING, Optional.of(operationId), active.payload());
    byte[] digest = identity.operationDigest(operationId).bytes();
    byte[] row = binding.keyCodec().deploymentRevocationV1(ByteKey.copyOf(digest));
    byte[] qualifier = binding.keyCodec().deploymentRevocationQualifierV1(ByteKey.copyOf(digest));
    doReturn(CompletableFuture.completedFuture(Result.create(new org.apache.hadoop.hbase.Cell[] {
        new KeyValue(row, binding.family(), qualifier, DeploymentControlMessages.encode(pending))})))
        .when(table).get(any(Get.class));
    try (var scope = RequestScope.withoutDeadline()) {
      assertEquals(pending, store.readRequired(pending.kind(), identity, Optional.of(operationId), scope)
          .toCompletableFuture().join());
      assertThrows(IllegalArgumentException.class,
          () -> store.readRequired(pending.kind(), identity, Optional.empty(), scope));
    }
  }

  @Test
  void unknownCasIsFollowedByStrongReadWithoutInferringTheWriteOutcome() {
    ByteKey operation = ByteKey.copyOf(new byte[16]);
    var revoking = new DeploymentControlRecord(active.kind(), identity, 2,
        DeploymentControlRecord.State.REVOKING, Optional.of(operation), active.payload());
    var revoked = new DeploymentControlRecord(active.kind(), identity, 3,
        DeploymentControlRecord.State.REVOKED, Optional.of(operation), active.payload());
    byte[] row = binding.keyCodec().deploymentBindingV1(identity.bindingDigest());
    byte[] qualifier = binding.keyCodec().deploymentBindingQualifierV1(identity.bindingDigest());
    doReturn(CompletableFuture.failedFuture(new BackendFailure(BackendFailure.Category.TIMEOUT)))
        .when(table).checkAndMutate(any(CheckAndMutate.class));
    doReturn(CompletableFuture.completedFuture(result(row, qualifier, revoking)),
        CompletableFuture.completedFuture(result(row, qualifier, active)),
        CompletableFuture.completedFuture(result(row, qualifier, revoked)))
        .when(table).get(any(Get.class));
    try (var scope = RequestScope.withoutDeadline()) {
      for (var visible : List.of(revoking, active, revoked)) {
        var failure = assertThrows(CompletionException.class,
            () -> store.compareAndSet(active, revoking, scope).toCompletableFuture().join());
        assertEquals(BackendFailure.Category.TIMEOUT,
            assertInstanceOf(BackendFailure.class, failure.getCause()).category());
        assertEquals(visible, store.readRequired(active.kind(), identity, Optional.empty(), scope)
            .toCompletableFuture().join());
      }
      var reads = ArgumentCaptor.forClass(Get.class);
      verify(table, org.mockito.Mockito.times(3)).get(reads.capture());
      assertTrue(reads.getAllValues().stream().allMatch(get -> get.getConsistency() == Consistency.STRONG));
    }
  }

  @Test
  void readRejectsEveryMismatchedIdentityComponentEvenUnderTheExpectedAddress() {
    byte[] row = binding.keyCodec().deploymentBindingV1(identity.bindingDigest());
    byte[] qualifier = binding.keyCodec().deploymentBindingQualifierV1(identity.bindingDigest());
    var otherDataset = new byte[32];
    otherDataset[0] = 1;
    var mismatches = List.of(
        new DeploymentIdentity("other", "group", identity.datasetDigest(), 1, "instance"),
        new DeploymentIdentity("trust", "other", identity.datasetDigest(), 1, "instance"),
        new DeploymentIdentity("trust", "group", ByteKey.copyOf(otherDataset), 1, "instance"),
        new DeploymentIdentity("trust", "group", identity.datasetDigest(), 2, "instance"),
        new DeploymentIdentity("trust", "group", identity.datasetDigest(), 1, "other"));
    for (var other : mismatches) {
      var record = new DeploymentControlRecord(active.kind(), other, 1,
          DeploymentControlRecord.State.ACTIVE, Optional.empty(), active.payload());
      doReturn(CompletableFuture.completedFuture(result(row, qualifier, record)))
          .when(table).get(any(Get.class));
      try (var scope = RequestScope.withoutDeadline()) {
        var failure = assertThrows(CompletionException.class, () -> store.readRequired(active.kind(),
            identity, Optional.empty(), scope).toCompletableFuture().join());
        assertEquals(BackendFailure.Category.UNAVAILABLE,
            assertInstanceOf(BackendFailure.class, failure.getCause()).category());
      }
    }
  }

  private Result result(byte[] row, byte[] qualifier, DeploymentControlRecord record) {
    return Result.create(new org.apache.hadoop.hbase.Cell[] {
        new KeyValue(row, binding.family(), qualifier, DeploymentControlMessages.encode(record))});
  }
}
