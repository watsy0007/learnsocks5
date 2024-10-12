defmodule Learnsocks5.Server do
  @doc """
  https://datatracker.ietf.org/doc/html/rfc1928
  """
  require Logger
  @listen_options [:binary, packet: 0, active: false, reuseaddr: true]
  @connect_ip4_options [:binary, :inet, packet: 0, active: false, reuseaddr: true]
  @connect_ip6_options [:binary, :inet6, packet: 0, active: false, reuseaddr: true]
  def listen(port) do
    {:ok, socket} = :gen_tcp.listen(port, @listen_options)
    Logger.info("Listening connections on port #{port}")
    loop_acceptor(socket)
  end

  defp loop_acceptor(socket) do
    {:ok, client} = :gen_tcp.accept(socket)

    {:ok, pid} =
      Task.Supervisor.start_child(Learnsocks5.TaskSupervisor, fn -> handle_socks5(client) end)

    :gen_tcp.controlling_process(client, pid)

    loop_acceptor(socket)
  end

  defp handle_socks5(client) do
    Logger.debug("Handling client: #{inspect(client)}")

    with :ok <- handshake(client),
         :ok <- valid_auth(client),
         {:ok, req} <- parse_target_ip(client),
         {:ok, conn} <- connect_target(req, client) do
      forwarding(conn, client)
    else
      _ -> exit(:shut_down)
    end
  end

  defp handshake(client) do
    case :gen_tcp.recv(client, 0) do
      {:ok, <<5, nmethods, _::bytes>>} when nmethods < 3 ->
        :gen_tcp.send(client, <<5, 255>>)
        {:error, "please support auth method"}

      {:ok, <<5, nmethods, methods::bytes-size(nmethods)>>} ->
        case methods |> to_charlist() |> Enum.member?(2) do
          true ->
            :gen_tcp.send(client, <<5, 2>>)

          false ->
            :gen_tcp.send(client, <<5, 255>>)
            {:error, "please support auth method"}
        end

      other ->
        other
    end
  end

  defp valid_auth(client) do
    case :gen_tcp.recv(client, 0) do
      {:ok, <<1, 0, p_len, password::bytes-size(p_len)>>} ->
        pass = password |> to_charlist()

        case pass == ~c"1" do
          true ->
            :gen_tcp.send(client, <<1, 0>>)

          false ->
            :gen_tcp.send(client, <<1, 1>>)
            {:error, "invalid password"}
        end

      other ->
        other
    end
  end

  defp parse_target_ip(client) do
    {:ok, conn_type} = :gen_tcp.recv(client, 0)

    case conn_type do
      <<5, 1, 0, 1, a, b, c, d, port::16>> ->
        Logger.debug("ip4 -> #{a}.#{b}.#{c}.#{d}:#{port}")
        {:ok, %{type: :ip4, ip: {a, b, c, d}, port: port}}

      <<5, 1, 0, 3, len, addr::bytes-size(len), port::16>> ->
        Logger.debug("host -> #{addr}:#{port}")
        addr_cl = to_charlist(addr)

        case :inet.getaddr(addr_cl, :inet) do
          {:ok, ip} ->
            type =
              cond do
                :inet.is_ipv4_address(ip) -> :ip4
                :inet.is_ipv6_address(ip) -> :ip6
                true -> :host
              end

            {:ok, %{type: type, ip: ip, port: port}}

          _ ->
            {:error, {:nxdomain, addr}}
        end

      <<5, 1, 0, 4, addr::bytes-16, port::16>> ->
        ip =
          for <<group::16 <- addr>> do
            group
          end
          # { x, x, x, x, x, x, x, x } representation
          |> List.to_tuple()
          # ::xx:xx:xx representation, :gen_tcp.connect only takes this one
          |> :inet.ntoa()

        Logger.debug("ip6 -> #{inspect(addr)} => #{inspect(ip)} :#{port}")

        {:ok, %{type: :ip6, ip: ip, port: port}}
    end
  end

  defp connect_target(%{type: type, ip: ip, port: port}, client) do
    opts =
      case type do
        :host -> @connect_ip4_options
        :ip4 -> @connect_ip4_options
        :ip6 -> @connect_ip6_options
      end

    case :gen_tcp.connect(ip, port, opts) do
      {:ok, socket} ->
        reply_connected(client)
        {:ok, socket}

      {:error, reason} ->
        Logger.error("Error on connect_target: #{reason}")
        reply_connect_error(reason, client)
        {:error, reason}
    end
  end

  defp reply_connected(client) do
    :gen_tcp.send(client, <<5, 0, 0, 1, 0, 0, 0, 0, 0, 0>>)
  end

  defp reply_connect_error(reason, client) do
    flag = reason_to_flag(reason)
    :gen_tcp.send(client, <<5, flag, 0, 1, 0, 0, 0, 0, 0, 0>>)
  end

  defp reason_to_flag(:nxdomain), do: 4
  defp reason_to_flag(:econnrefused), do: 5

  defp forwarding(from, to) do
    {:ok, fpid} =
      Task.Supervisor.start_child(Learnsocks5.TaskSupervisor, fn -> proxy(from, to) end)

    :gen_tcp.controlling_process(from, fpid)

    {:ok, tpid} =
      Task.Supervisor.start_child(Learnsocks5.TaskSupervisor, fn -> proxy(to, from) end)

    :gen_tcp.controlling_process(to, tpid)
  end

  defp proxy(from, to) do
    with {:ok, data} <- :gen_tcp.recv(from, 0),
         :ok <- :gen_tcp.send(to, data) do
      proxy(from, to)
    else
      _ ->
        :gen_tcp.close(from)
        :gen_tcp.close(to)
    end
  end
end
