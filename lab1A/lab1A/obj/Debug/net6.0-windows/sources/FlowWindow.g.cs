﻿#pragma checksum "..\..\..\..\sources\FlowWindow.xaml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "2EE09E7E41D2CDA0F7B862F77B38AFC702D5A783"
//------------------------------------------------------------------------------
// <auto-generated>
//     此代码由工具生成。
//     运行时版本:4.0.30319.42000
//
//     对此文件的更改可能会导致不正确的行为，并且如果
//     重新生成代码，这些更改将会丢失。
// </auto-generated>
//------------------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Controls.Ribbon;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Ink;
using System.Windows.Input;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Shell;
using lab1A.sources;


namespace lab1A.sources {
    
    
    /// <summary>
    /// FlowWindow
    /// </summary>
    public partial class FlowWindow : System.Windows.Window, System.Windows.Markup.IComponentConnector, System.Windows.Markup.IStyleConnector {
        
        
        #line 13 "..\..\..\..\sources\FlowWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox tb_filter;
        
        #line default
        #line hidden
        
        
        #line 27 "..\..\..\..\sources\FlowWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.DataGrid dg_packets;
        
        #line default
        #line hidden
        
        
        #line 77 "..\..\..\..\sources\FlowWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button btn_StopCapture;
        
        #line default
        #line hidden
        
        
        #line 78 "..\..\..\..\sources\FlowWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.Button btn_RestartCapture;
        
        #line default
        #line hidden
        
        
        #line 80 "..\..\..\..\sources\FlowWindow.xaml"
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1823:AvoidUnusedPrivateFields")]
        internal System.Windows.Controls.TextBox tb_raw_packet;
        
        #line default
        #line hidden
        
        private bool _contentLoaded;
        
        /// <summary>
        /// InitializeComponent
        /// </summary>
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "7.0.4.0")]
        public void InitializeComponent() {
            if (_contentLoaded) {
                return;
            }
            _contentLoaded = true;
            System.Uri resourceLocater = new System.Uri("/lab1A;component/sources/flowwindow.xaml", System.UriKind.Relative);
            
            #line 1 "..\..\..\..\sources\FlowWindow.xaml"
            System.Windows.Application.LoadComponent(this, resourceLocater);
            
            #line default
            #line hidden
        }
        
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "7.0.4.0")]
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Never)]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Design", "CA1033:InterfaceMethodsShouldBeCallableByChildTypes")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily")]
        void System.Windows.Markup.IComponentConnector.Connect(int connectionId, object target) {
            switch (connectionId)
            {
            case 1:
            
            #line 8 "..\..\..\..\sources\FlowWindow.xaml"
            ((lab1A.sources.FlowWindow)(target)).Loaded += new System.Windows.RoutedEventHandler(this.Window_Loaded);
            
            #line default
            #line hidden
            
            #line 9 "..\..\..\..\sources\FlowWindow.xaml"
            ((lab1A.sources.FlowWindow)(target)).Closing += new System.ComponentModel.CancelEventHandler(this.Window_Closing);
            
            #line default
            #line hidden
            return;
            case 2:
            this.tb_filter = ((System.Windows.Controls.TextBox)(target));
            
            #line 14 "..\..\..\..\sources\FlowWindow.xaml"
            this.tb_filter.KeyUp += new System.Windows.Input.KeyEventHandler(this.tb_filter_KeyUp);
            
            #line default
            #line hidden
            return;
            case 3:
            this.dg_packets = ((System.Windows.Controls.DataGrid)(target));
            return;
            case 5:
            this.btn_StopCapture = ((System.Windows.Controls.Button)(target));
            
            #line 77 "..\..\..\..\sources\FlowWindow.xaml"
            this.btn_StopCapture.Click += new System.Windows.RoutedEventHandler(this.btn_StopCapture_Click);
            
            #line default
            #line hidden
            return;
            case 6:
            this.btn_RestartCapture = ((System.Windows.Controls.Button)(target));
            
            #line 78 "..\..\..\..\sources\FlowWindow.xaml"
            this.btn_RestartCapture.Click += new System.Windows.RoutedEventHandler(this.btn_RestartCapture_Click);
            
            #line default
            #line hidden
            return;
            case 7:
            this.tb_raw_packet = ((System.Windows.Controls.TextBox)(target));
            return;
            }
            this._contentLoaded = true;
        }
        
        [System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [System.CodeDom.Compiler.GeneratedCodeAttribute("PresentationBuildTasks", "7.0.4.0")]
        [System.ComponentModel.EditorBrowsableAttribute(System.ComponentModel.EditorBrowsableState.Never)]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Design", "CA1033:InterfaceMethodsShouldBeCallableByChildTypes")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1800:DoNotCastUnnecessarily")]
        [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Maintainability", "CA1502:AvoidExcessiveComplexity")]
        void System.Windows.Markup.IStyleConnector.Connect(int connectionId, object target) {
            System.Windows.EventSetter eventSetter;
            switch (connectionId)
            {
            case 4:
            eventSetter = new System.Windows.EventSetter();
            eventSetter.Event = System.Windows.UIElement.MouseRightButtonUpEvent;
            
            #line 35 "..\..\..\..\sources\FlowWindow.xaml"
            eventSetter.Handler = new System.Windows.Input.MouseButtonEventHandler(this.dg_packets_DataGridCell_MouseRightButtonUp);
            
            #line default
            #line hidden
            ((System.Windows.Style)(target)).Setters.Add(eventSetter);
            eventSetter = new System.Windows.EventSetter();
            eventSetter.Event = System.Windows.UIElement.MouseLeftButtonUpEvent;
            
            #line 36 "..\..\..\..\sources\FlowWindow.xaml"
            eventSetter.Handler = new System.Windows.Input.MouseButtonEventHandler(this.dg_packets_DataGridCell_MouseLeftButtonUp);
            
            #line default
            #line hidden
            ((System.Windows.Style)(target)).Setters.Add(eventSetter);
            break;
            }
        }
    }
}

