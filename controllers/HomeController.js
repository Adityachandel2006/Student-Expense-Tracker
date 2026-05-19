class HomeController {
  // Render home page
  static getHome = (req, res) => {
    res.render('home');
  };
}

module.exports = HomeController;
