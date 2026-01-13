namespace VpnApp.WinForms
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.ComboBox ModeCombo;
        private System.Windows.Forms.TextBox EndpointText;
        private System.Windows.Forms.Button ConnectButton;
        private System.Windows.Forms.Button DisconnectButton;
        private System.Windows.Forms.Button SettingsButton;
        private System.Windows.Forms.Button UsersButton;
        private System.Windows.Forms.Label StatusLabel;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.ModeCombo = new System.Windows.Forms.ComboBox();
            this.EndpointText = new System.Windows.Forms.TextBox();
            this.ConnectButton = new System.Windows.Forms.Button();
            this.DisconnectButton = new System.Windows.Forms.Button();
            this.SettingsButton = new System.Windows.Forms.Button();
            this.UsersButton = new System.Windows.Forms.Button();
            this.StatusLabel = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // ModeCombo
            // 
            this.ModeCombo.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.ModeCombo.Items.AddRange(new object[] {
            "Client",
            "Server"});
            this.ModeCombo.Location = new System.Drawing.Point(12, 12);
            this.ModeCombo.Name = "ModeCombo";
            this.ModeCombo.Size = new System.Drawing.Size(121, 23);
            this.ModeCombo.TabIndex = 0;
            // 
            // EndpointText
            // 
            this.EndpointText.Location = new System.Drawing.Point(12, 50);
            this.EndpointText.Name = "EndpointText";
            this.EndpointText.PlaceholderText = "wss://relay.example.com:443";
            this.EndpointText.Size = new System.Drawing.Size(360, 23);
            this.EndpointText.TabIndex = 1;
            // 
            // ConnectButton
            // 
            this.ConnectButton.Location = new System.Drawing.Point(12, 90);
            this.ConnectButton.Name = "ConnectButton";
            this.ConnectButton.Size = new System.Drawing.Size(75, 23);
            this.ConnectButton.TabIndex = 2;
            this.ConnectButton.Text = "Connect";
            this.ConnectButton.UseVisualStyleBackColor = true;
            this.ConnectButton.Click += new System.EventHandler(this.ConnectButton_Click);
            // 
            // DisconnectButton
            // 
            this.DisconnectButton.Location = new System.Drawing.Point(93, 90);
            this.DisconnectButton.Name = "DisconnectButton";
            this.DisconnectButton.Size = new System.Drawing.Size(85, 23);
            this.DisconnectButton.TabIndex = 3;
            this.DisconnectButton.Text = "Disconnect";
            this.DisconnectButton.UseVisualStyleBackColor = true;
            this.DisconnectButton.Click += new System.EventHandler(this.DisconnectButton_Click);
            // 
            // SettingsButton
            // 
            this.SettingsButton.Location = new System.Drawing.Point(184, 90);
            this.SettingsButton.Name = "SettingsButton";
            this.SettingsButton.Size = new System.Drawing.Size(75, 23);
            this.SettingsButton.TabIndex = 4;
            this.SettingsButton.Text = "Settings";
            this.SettingsButton.UseVisualStyleBackColor = true;
            this.SettingsButton.Click += new System.EventHandler(this.SettingsButton_Click);
            // 
            // UsersButton
            // 
            this.UsersButton.Location = new System.Drawing.Point(265, 90);
            this.UsersButton.Name = "UsersButton";
            this.UsersButton.Size = new System.Drawing.Size(75, 23);
            this.UsersButton.TabIndex = 5;
            this.UsersButton.Text = "Users";
            this.UsersButton.UseVisualStyleBackColor = true;
            this.UsersButton.Click += new System.EventHandler(this.UsersButton_Click);
            // 
            // StatusLabel
            // 
            this.StatusLabel.AutoSize = true;
            this.StatusLabel.Location = new System.Drawing.Point(12, 130);
            this.StatusLabel.Name = "StatusLabel";
            this.StatusLabel.Size = new System.Drawing.Size(74, 15);
            this.StatusLabel.TabIndex = 6;
            this.StatusLabel.Text = "Disconnected";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(384, 161);
            this.Controls.Add(this.StatusLabel);
            this.Controls.Add(this.UsersButton);
            this.Controls.Add(this.SettingsButton);
            this.Controls.Add(this.DisconnectButton);
            this.Controls.Add(this.ConnectButton);
            this.Controls.Add(this.EndpointText);
            this.Controls.Add(this.ModeCombo);
            this.MaximizeBox = false;
            this.Name = "MainForm";
            this.Text = "BeyondVPN";
            this.ResumeLayout(false);
            this.PerformLayout();

        }
    }
}
