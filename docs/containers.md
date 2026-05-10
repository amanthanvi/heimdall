# Containers and Devcontainers

Mounting an agent socket into a container delegates signing capability to that container. Heimdall never mounts sockets silently.

Use:

```sh
heimdall doctor container
heimdall bridge container
```

The snippet is explicit and should be adapted only for trusted images and scoped workflows. Do not copy private keys into images.

For workflows that need a narrower socket than the ambient agent, define a session bridge and launch a child command with:

```sh
heimdall run --context <ctx> --bridge <bridge> -- docker run ...
```

The bridge socket is scoped to that child process and cleaned up after exit. Persistent container bridge daemons remain out of scope.
