using Microsoft.AspNetCore.SignalR;
using System.Threading.Channels;

namespace Phalanx.Console.Hubs;

public class AlertHub : Hub
{
    private readonly ChannelWriter<bool> _signal;

    public AlertHub(Channel<bool> alertChannel)
    {
        _signal = alertChannel.Writer;
    }

    public async Task BroadcastAlert(object alert)
    {
        await Clients.All.SendAsync("ReceiveAlert", alert);
        _signal.TryWrite(true);
    }
}
