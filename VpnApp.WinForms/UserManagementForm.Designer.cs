namespace VpnApp.WinForms
{
    partial class UserManagementForm
    {
        private System.ComponentModel.IContainer components = null;
        private System.Windows.Forms.Label LabelInfo;

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
            this.LabelInfo = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // LabelInfo
            // 
            this.LabelInfo.AutoSize = true;
            this.LabelInfo.Location = new System.Drawing.Point(12, 9);
            this.LabelInfo.Name = "LabelInfo";
            this.LabelInfo.Size = new System.Drawing.Size(262, 15);
            this.LabelInfo.TabIndex = 0;
            this.LabelInfo.Text = "User management UI placeholder for admin.";
            // 
            // UserManagementForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(384, 61);
            this.Controls.Add(this.LabelInfo);
            this.MaximizeBox = false;
            this.Name = "UserManagementForm";
            this.Text = "Users";
            this.ResumeLayout(false);
            this.PerformLayout();

        }
    }
}
