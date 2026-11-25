package io.etcdhbase.hbase.storage;

import io.etcdhbase.core.auth.DeploymentControlRecord;
import io.etcdhbase.core.auth.DeploymentControlStore;
import io.etcdhbase.core.auth.DeploymentIdentity;
import io.etcdhbase.core.bytes.ByteKey;
import io.etcdhbase.core.error.BackendFailure;
import io.etcdhbase.core.request.RequestScope;
import io.etcdhbase.hbase.api.HBaseConnectionFactory;
import io.etcdhbase.hbase.codec.DeploymentControlMessages;
import io.etcdhbase.hbase.connection.HBaseRequestContext;
import io.etcdhbase.hbase.error.HBaseFailures;
import io.etcdhbase.spi.identity.AuthorizedBackendIdentity;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import org.apache.hadoop.hbase.CellUtil;
import org.apache.hadoop.hbase.client.AsyncConnection;
import org.apache.hadoop.hbase.client.AsyncTable;
import org.apache.hadoop.hbase.client.CheckAndMutate;
import org.apache.hadoop.hbase.client.Consistency;
import org.apache.hadoop.hbase.client.Durability;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;

/** Installer-only storage primitive; domain authorization and payload validation are separate. */
public final class HBaseDeploymentControlStore implements DeploymentControlStore.Installer {
  private final AsyncConnection connection;
  private final AuthControlBinding binding;

  HBaseDeploymentControlStore(AsyncConnection connection, AuthControlBinding binding) {
    this.connection = Objects.requireNonNull(connection, "connection");
    this.binding = Objects.requireNonNull(binding, "binding");
  }

  /** Caller must provision a separately authorized installer identity; this does not grant it. */
  public static CompletableFuture<HBaseDeploymentControlStore> openInstaller(
      HBaseConnectionFactory connections, AuthorizedBackendIdentity installer,
      AuthControlBinding binding, RequestScope scope) {
    Objects.requireNonNull(connections, "connections");
    Objects.requireNonNull(installer, "installer");
    Objects.requireNonNull(binding, "binding");
    Objects.requireNonNull(scope, "scope");
    return new HBaseRequestContext(scope).borrowConnection(connections, installer)
        .thenCompose(connection -> HBaseRequestCompletion.startRequest(scope, () ->
            connection.getAdmin().getDescriptor(binding.table()).thenApply(descriptor -> {
              binding.validate(descriptor);
              return new HBaseDeploymentControlStore(connection, binding);
            }))).exceptionallyCompose(failure -> CompletableFuture.failedFuture(
                HBaseFailures.classify(failure)));
  }

  @Override
  public CompletionStage<DeploymentControlRecord> readRequired(DeploymentControlRecord.Kind kind,
      DeploymentIdentity identity, Optional<ByteKey> operationId, RequestScope scope) {
    Address address = address(kind, identity, operationId);
    return execute(scope, table -> table.get(new Get(address.row())
        .setConsistency(Consistency.STRONG).addColumn(binding.family(), address.qualifier())))
        .thenApply(result -> decode(result, address, kind, identity, operationId));
  }

  @Override
  public CompletionStage<Boolean> createIfAbsent(DeploymentControlRecord record, RequestScope scope) {
    Objects.requireNonNull(record, "record");
    if (!record.isInitial()) return CompletableFuture.failedFuture(
        new IllegalArgumentException("deployment control creation requires an initial state"));
    Address address = address(record);
    byte[] value = DeploymentControlMessages.encode(record);
    Put put = new Put(address.row()).setDurability(Durability.SYNC_WAL)
        .addColumn(binding.family(), address.qualifier(), value);
    return execute(scope, table -> table.checkAndMutate(CheckAndMutate.newBuilder(address.row())
        .ifNotExists(binding.family(), address.qualifier()).build(put)).thenApply(result -> result.isSuccess()));
  }

  @Override
  public CompletionStage<Boolean> compareAndSet(DeploymentControlRecord observed,
      DeploymentControlRecord replacement, RequestScope scope) {
    Objects.requireNonNull(observed, "observed");
    if (!observed.allowsReplacement(replacement)) return CompletableFuture.failedFuture(
        new IllegalArgumentException("invalid deployment control transition"));
    Address address = address(observed);
    byte[] oldValue = DeploymentControlMessages.encode(observed);
    byte[] newValue = DeploymentControlMessages.encode(replacement);
    Put put = new Put(address.row()).setDurability(Durability.SYNC_WAL)
        .addColumn(binding.family(), address.qualifier(), newValue);
    return execute(scope, table -> table.checkAndMutate(CheckAndMutate.newBuilder(address.row())
        .ifEquals(binding.family(), address.qualifier(), oldValue).build(put))
        .thenApply(result -> result.isSuccess()));
  }

  private DeploymentControlRecord decode(Result result, Address address,
      DeploymentControlRecord.Kind kind, DeploymentIdentity identity, Optional<ByteKey> operationId) {
    if (result == null || result.isEmpty() || !Arrays.equals(address.row(), result.getRow())
        || result.rawCells() == null || result.rawCells().length != 1
        || !CellUtil.matchingFamily(result.rawCells()[0], binding.family())
        || !CellUtil.matchingQualifier(result.rawCells()[0], address.qualifier())) {
      throw unavailable();
    }
    try {
      DeploymentControlRecord record = DeploymentControlMessages.decode(
          result.getValue(binding.family(), address.qualifier()));
      if (record.kind() != kind || !record.identity().equals(identity)
          || kind == DeploymentControlRecord.Kind.REVOCATION_V1
              && !record.operationId().equals(operationId)) throw unavailable();
      return record;
    } catch (IllegalArgumentException invalid) {
      throw unavailable();
    }
  }

  private Address address(DeploymentControlRecord record) {
    return address(record.kind(), record.identity(), record.kind() == DeploymentControlRecord.Kind.BINDING_V1
        ? Optional.empty() : record.operationId());
  }

  private Address address(DeploymentControlRecord.Kind kind, DeploymentIdentity identity,
      Optional<ByteKey> operationId) {
    Objects.requireNonNull(kind, "kind");
    Objects.requireNonNull(identity, "identity");
    Objects.requireNonNull(operationId, "operationId");
    if (!binding.trustDomain().equals(identity.trustDomain())
        || kind == DeploymentControlRecord.Kind.BINDING_V1 && operationId.isPresent()
        || kind == DeploymentControlRecord.Kind.REVOCATION_V1 && operationId.isEmpty()) {
      throw new IllegalArgumentException("deployment control address does not match its binding");
    }
    var codec = binding.keyCodec();
    ByteKey digest = kind == DeploymentControlRecord.Kind.BINDING_V1 ? identity.bindingDigest()
        : identity.operationDigest(operationId.orElseThrow());
    return kind == DeploymentControlRecord.Kind.BINDING_V1
        ? new Address(codec.deploymentBindingV1(digest), codec.deploymentBindingQualifierV1(digest))
        : new Address(codec.deploymentRevocationV1(digest), codec.deploymentRevocationQualifierV1(digest));
  }

  private <T> CompletableFuture<T> execute(RequestScope scope,
      Function<AsyncTable<?>, CompletableFuture<T>> operation) {
    Objects.requireNonNull(scope, "scope");
    return HBaseRequestCompletion.startRequest(scope, () -> {
      long timeout = Math.max(1, Math.min(TimeUnit.SECONDS.toNanos(30), scope.remainingDeadlineNanos()));
      AsyncTable<?> table = connection.getTableBuilder(binding.table())
          .setOperationTimeout(timeout, TimeUnit.NANOSECONDS).setRpcTimeout(timeout, TimeUnit.NANOSECONDS)
          .setReadRpcTimeout(timeout, TimeUnit.NANOSECONDS).setWriteRpcTimeout(timeout, TimeUnit.NANOSECONDS)
          .build();
      return operation.apply(table);
    });
  }

  private static CompletionException unavailable() {
    return new CompletionException(new BackendFailure(BackendFailure.Category.UNAVAILABLE));
  }

  private record Address(byte[] row, byte[] qualifier) {}
}
