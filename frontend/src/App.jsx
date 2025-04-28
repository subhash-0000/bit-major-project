import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { 
  AppBar, Toolbar, Typography, Container, Button, Box, CssBaseline,
  Tabs, Tab, Paper, ThemeProvider, createTheme
} from '@mui/material';
import { 
  Dashboard as DashboardIcon,
  Send as SendIcon,
  List as ListIcon,
  Security as SecurityIcon
} from '@mui/icons-material';
import AlertForm from './components/AlertForm';
import AlertList from './components/AlertList';

// Create a theme with better colors
const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#f50057',
    },
  },
  components: {
    MuiAppBar: {
      defaultProps: {
        elevation: 0,
      },
      styleOverrides: {
        root: {
          borderBottom: '1px solid rgba(0, 0, 0, 0.12)',
        },
      },
    },
  },
});

function TabPanel(props) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`tabpanel-${index}`}
      aria-labelledby={`tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

function App() {
  const [tabValue, setTabValue] = React.useState(0);

  const handleTabChange = (event, newValue) => {
    setTabValue(newValue);
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        <AppBar position="static" color="default">
          <Toolbar>
            <SecurityIcon sx={{ mr: 2 }} color="primary" />
            <Typography variant="h6" color="inherit" sx={{ flexGrow: 1 }}>
              Security Alert Management System
            </Typography>
          </Toolbar>
        </AppBar>

        <Paper sx={{ borderRadius: 0 }}>
          <Tabs 
            value={tabValue} 
            onChange={handleTabChange} 
            indicatorColor="primary"
            textColor="primary"
            variant="fullWidth"
          >
            <Tab icon={<SendIcon />} label="PROCESS ALERT" />
            <Tab icon={<ListIcon />} label="VIEW ALERTS" />
          </Tabs>
        </Paper>

        <Container maxWidth="lg" sx={{ flexGrow: 1 }}>
          <TabPanel value={tabValue} index={0}>
            <AlertForm />
          </TabPanel>
          <TabPanel value={tabValue} index={1}>
            <AlertList />
          </TabPanel>
        </Container>

        <Box component="footer" sx={{ py: 3, px: 2, mt: 'auto', backgroundColor: 'rgba(0, 0, 0, 0.03)' }}>
          <Container maxWidth="lg">
            <Typography variant="body2" color="text.secondary" align="center">
              Security Alert Management System © {new Date().getFullYear()}
            </Typography>
          </Container>
        </Box>
      </Box>
    </ThemeProvider>
  );
}

export default App;
