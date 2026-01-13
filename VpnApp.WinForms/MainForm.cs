using System;
using System.Windows.Forms;

namespace VpnApp.WinForms
{
    public partial class MainForm : Form
    {
        private readonly VpnController _controller;

        public MainForm()
        {
            InitializeComponent();
            _controller = new VpnController();
            ModeCombo.SelectedIndex = 0;
        }

        private void ConnectButton_Click(object sender, EventArgs e)
        {
            var mode = ModeCombo.SelectedItem?.ToString();
            if (string.Equals(mode, "Client", StringComparison.OrdinalIgnoreCase))
            {
                _controller.StartClient(EndpointText.Text);
                StatusLabel.Text = "Client connected (stub).";
            }
            else
            {
                _controller.StartServer(EndpointText.Text);
                StatusLabel.Text = "Server listening (stub).";
            }
        }

        private void DisconnectButton_Click(object sender, EventArgs e)
        {
            var mode = ModeCombo.SelectedItem?.ToString();
            if (string.Equals(mode, "Client", StringComparison.OrdinalIgnoreCase))
            {
                _controller.StopClient();
                StatusLabel.Text = "Client stopped.";
            }
            else
            {
                _controller.StopServer();
                StatusLabel.Text = "Server stopped.";
            }
        }

        private void SettingsButton_Click(object sender, EventArgs e)
        {
            using (var form = new SettingsForm())
            {
                form.ShowDialog(this);
            }
        }

        private void UsersButton_Click(object sender, EventArgs e)
        {
            using (var form = new UserManagementForm())
            {
                form.ShowDialog(this);
            }
        }
    }
}
